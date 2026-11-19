package flow

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"netflow-plus-v2/internal/ipfix"
)

const uptimeWrap = time.Duration(1<<32) * time.Millisecond

// ExporterEstimatedTime requires both timestamps and a plausible exporter
// interval. Legacy estimates and receive-time fallbacks cannot authorize DNS.
const ExporterEstimatedTime = "exporter_estimated"

// ExporterTimeUncertainty accounts for the header's second precision and
// the allowed deviation from a settled receive/export clock baseline.
const ExporterTimeUncertainty = 2 * time.Second

const maxClockDeviation = time.Second

// Normalizer converts decoded IPFIX messages into flows.
type Normalizer struct {
	topo          *Topology
	activeTimeout time.Duration
	flowPort      uint16

	mu     sync.Mutex
	clocks map[netip.Addr]*exporterClock
}

// exporterClock tracks the offset between an exporter's clock and ours.
// The minimum receive/export gap over recent windows approximates the
// offset. Clock jumps, unusually late datagrams and warm-up are rejected.
type exporterClock struct {
	curMin, prevMin time.Duration
	windowStart     time.Time
	sysInitMs       uint64
	reboots         int
	firstExport     uint32
	lastExport      uint32
}

// ClockInfo describes an exporter's clock as seen by the collector.
type ClockInfo struct {
	Exporter string    `json:"exporter"`
	OffsetMs int64     `json:"offsetMs"` // collector clock minus router clock
	BootTime time.Time `json:"bootTime"`
	Reboots  int       `json:"reboots"` // reboots observed since the collector started
}

// NewNormalizer creates a normalizer. activeTimeout is the router's
// active-flow-timeout; flowPort is the UDP port the collector listens on, used
// to drop the router's own export stream.
func NewNormalizer(topo *Topology, activeTimeout time.Duration, flowPort uint16) *Normalizer {
	return &Normalizer{topo: topo, activeTimeout: activeTimeout, flowPort: flowPort, clocks: map[netip.Addr]*exporterClock{}}
}

// Fork makes speculative normalization independent of accepted clock and
// topology state, so rejected datagrams cannot poison later calculations.
func (n *Normalizer) Fork() *Normalizer {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.topo.mu.RLock()
	defer n.topo.mu.RUnlock()
	t := &Topology{local: append([]netip.Prefix(nil), n.topo.local...), sites: append([]Site(nil), n.topo.sites...), router: map[netip.Addr]struct{}{}, fromZero: map[netip.Addr]struct{}{}, toZero: map[netip.Addr]struct{}{}}
	for k := range n.topo.router {
		t.router[k] = struct{}{}
	}
	for k := range n.topo.fromZero {
		t.fromZero[k] = struct{}{}
	}
	for k := range n.topo.toZero {
		t.toZero[k] = struct{}{}
	}
	out := NewNormalizer(t, n.activeTimeout, n.flowPort)
	for k, v := range n.clocks {
		c := *v
		out.clocks[k] = &c
	}
	return out
}

// Normalize converts one message. rebooted is true when the exporter's boot
// time changed since the previous message.
func (n *Normalizer) Normalize(exporter netip.Addr, recv time.Time, msg *ipfix.Message) (flows []Flow, rebooted bool) {
	n.topo.LearnRouter(exporter)
	var boot uint64
	mixedBoot := false
	for _, record := range msg.Records {
		sample := record.SysInitMs
		if sample == 0 || sample >= (uint64(msg.ExportTime)+1)*1000 {
			continue
		}
		if boot != 0 && max(boot, sample)-min(boot, sample) > uint64(maxClockDeviation.Milliseconds()) {
			mixedBoot = true
		}
		boot = sample
	}
	var offset time.Duration
	var clockReliable bool
	if !mixedBoot {
		offset, clockReliable, rebooted = n.offset(exporter, recv, msg.ExportTime, boot)
	}
	flows = make([]Flow, 0, len(msg.Records))
	for i := range msg.Records {
		r := &msg.Records[i]
		if r.Proto == 17 && r.Src == exporter && r.DstPort == n.flowPort {
			continue // the export stream itself
		}
		f, ok := n.classify(r)
		if !ok {
			continue
		}
		if mixedBoot || r.SysInitMs == 0 || r.SysInitMs >= (uint64(msg.ExportTime)+1)*1000 || !r.HasStartUptime || !r.HasEndUptime || msg.ExportTime == 0 {
			f.Start, f.End, f.TimeQuality = recv, recv, "receive_only"
		} else {
			var reliable bool
			f.Start, f.End, reliable = n.interval(r, recv, offset)
			f.TimeQuality = "receive_only"
			if reliable && clockReliable {
				f.TimeQuality = ExporterEstimatedTime
			} else if reliable {
				f.TimeQuality = "unreliable_exporter_time"
			}
		}
		f.Proto, f.Bytes, f.Packets, f.InIf, f.OutIf = r.Proto, r.Bytes, r.Packets, r.InIf, r.OutIf
		flows = append(flows, f)
	}
	return flows, rebooted
}

// classify applies the NAT inside view and zone rules measured against
// RouterOS 7.20: upload records carry the LAN source plus postNATSource (the
// WAN address); download records are addressed to the WAN address and carry
// the LAN host in postNATDestination.
func (n *Normalizer) classify(r *ipfix.Record) (Flow, bool) {
	var f Flow
	natDst := r.NatDst.IsValid() && !r.NatDst.IsUnspecified() && r.NatDst != r.Dst
	natSrc := r.NatSrc.IsValid() && !r.NatSrc.IsUnspecified() && r.NatSrc != r.Src
	switch {
	case natDst:
		f.Dir, f.Zone = Down, ZoneWAN
		f.LocalIP, f.LocalPort = r.NatDst, r.NatDstPort
		f.RemoteIP, f.RemotePort = r.Src, r.SrcPort
		f.PublicIP, f.PublicPort = r.Dst, r.DstPort
		n.topo.LearnRouter(r.Dst)
	case natSrc:
		f.Dir, f.Zone = Up, ZoneWAN
		f.LocalIP, f.LocalPort = r.Src, r.SrcPort
		f.RemoteIP, f.RemotePort = r.Dst, r.DstPort
		f.PublicIP, f.PublicPort = r.NatSrc, r.NatSrcPort
		n.topo.LearnRouter(r.NatSrc)
	default:
		if !r.Src.IsValid() || !r.Dst.IsValid() {
			return f, false
		}
		// Interface 0 on the way out means the packet was delivered to the
		// router itself (or was a broadcast it received). Interface 0 on the
		// way in is NOT a reliable sign of router-originated traffic: RouterOS
		// also reports it for some ICMP and reply packets of forwarded
		// connections. So only the outbound side is used as a hint, and an
		// address is accepted as the router's own only when it is seen on both
		// sides.
		n.topo.ObserveLocalDelivery(r.Src, r.InIf == 0, r.Dst, r.OutIf == 0)
		srcRouter, dstRouter := false, r.OutIf == 0
		side := n.topo.Classify(r.Src, r.Dst, srcRouter, dstRouter)
		if side.Drop {
			return f, false
		}
		f.Zone, f.Site, f.Router = side.Zone, side.Site, side.Router
		if side.LocalIsSrc {
			f.Dir = Up
			f.LocalIP, f.LocalPort, f.RemoteIP, f.RemotePort = r.Src, r.SrcPort, r.Dst, r.DstPort
		} else {
			f.Dir = Down
			f.LocalIP, f.LocalPort, f.RemoteIP, f.RemotePort = r.Dst, r.DstPort, r.Src, r.SrcPort
		}
	}
	if r.Proto == 1 || r.Proto == 58 { // ICMP has no ports; keep the key stable across directions
		f.LocalPort, f.RemotePort = 0, 0
	}
	// The source MAC is the LAN device only on records that entered from it.
	if f.Dir == Up && !f.Router && r.InIf != 0 && r.SrcMAC != [6]byte{} && r.SrcMAC[0]&1 == 0 {
		f.MAC = FormatMAC(r.SrcMAC)
	}
	return f, true
}

// interval returns the span of collector time the record's counters cover.
// RouterOS stamps flowEnd about one inactive timeout before it exports, but a
// record that hit the active timeout still counts every packet up to the
// export moment, so its bytes are spread up to the receive time.
func (n *Normalizer) interval(r *ipfix.Record, recv time.Time, offset time.Duration) (time.Time, time.Time, bool) {
	boot := time.UnixMilli(int64(r.SysInitMs)).Add(offset)
	wall := func(uptimeMs uint32) time.Time {
		t := boot.Add(time.Duration(uptimeMs) * time.Millisecond)
		for recv.Sub(t) > uptimeWrap/2 { // the 32-bit uptime counter wraps every 49.7 days
			t = t.Add(uptimeWrap)
		}
		return t
	}
	start, end := wall(r.StartUptimeMs), wall(r.EndUptimeMs)
	dur := time.Duration(r.EndUptimeMs-r.StartUptimeMs) * time.Millisecond
	if start.After(end) || end.After(recv) || recv.Sub(start) > 2*time.Hour || end.Sub(start) != dur {
		return recv, recv, false
	}
	if dur >= n.activeTimeout-1500*time.Millisecond {
		end = recv
	}
	return start, end, true
}

func differentBoot(a, b uint64) bool {
	return max(a, b)-min(a, b) > 10_000
}

func (n *Normalizer) offset(exporter netip.Addr, recv time.Time, exportTime uint32, boot uint64) (time.Duration, bool, bool) {
	if exportTime == 0 || boot == 0 {
		return 0, false, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	d := recv.Sub(time.Unix(int64(exportTime), 0))
	c := n.clocks[exporter]
	reboots := 0
	rebooted := false
	if c != nil {
		reboots = c.reboots
		rebooted = differentBoot(boot, c.sysInitMs)
		if rebooted {
			reboots++
		}
	}
	if c == nil || rebooted || max(boot, c.sysInitMs)-min(boot, c.sysInitMs) > uint64(maxClockDeviation.Milliseconds()) ||
		d < min(c.curMin, c.prevMin)-maxClockDeviation || recv.Sub(c.windowStart) > 4*time.Minute {
		c = &exporterClock{curMin: d, prevMin: d, windowStart: recv, sysInitMs: boot, reboots: reboots, firstExport: exportTime, lastExport: exportTime}
		n.clocks[exporter] = c
		return d, false, rebooted
	}
	if exportTime < c.lastExport {
		return min(c.curMin, c.prevMin), false, false
	}
	c.lastExport = exportTime
	if recv.Sub(c.windowStart) > 2*time.Minute {
		c.prevMin, c.curMin, c.windowStart = c.curMin, d, recv
	}
	if d < c.curMin {
		c.curMin = d
	}
	offset := min(c.curMin, c.prevMin)
	return offset, exportTime > c.firstExport && d-offset <= maxClockDeviation, false
}

// Clocks reports the clock state of every exporter seen.
func (n *Normalizer) Clocks() []ClockInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]ClockInfo, 0, len(n.clocks))
	for a, c := range n.clocks {
		off := min(c.curMin, c.prevMin)
		out = append(out, ClockInfo{
			Exporter: a.String(),
			OffsetMs: off.Milliseconds(),
			BootTime: time.UnixMilli(int64(c.sysInitMs)).Add(off),
			Reboots:  c.reboots,
		})
	}
	return out
}

// FormatMAC renders a MAC address in lower-case colon form.
func FormatMAC(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}
