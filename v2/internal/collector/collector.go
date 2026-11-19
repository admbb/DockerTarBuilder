// Package collector receives a separate RouterOS IPFIX stream for V2.
package collector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/ipfix"
	"netflow-plus-v2/internal/storage"
	"sync"
	"time"
)

type Collector struct {
	mu                  sync.Mutex
	Store               *storage.Store
	Decoder             *ipfix.Decoder
	Normalizer          *flow.Normalizer
	Allowed             map[netip.Addr]bool
	IgnoreExportTargets map[netip.AddrPort]bool
}

// Handle decodes and atomically records one datagram. Packets containing
// unrecognized templates are not accounted as complete.
func (c *Collector) Handle(ctx context.Context, exporter netip.Addr, received time.Time, packet []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exporter = exporter.Unmap()
	if c.Store == nil || c.Decoder == nil || c.Normalizer == nil {
		return false, errors.New("collector is not configured")
	}
	if !c.Allowed[exporter] {
		return false, errors.New("exporter not allowed")
	}
	digest := sha256.Sum256(packet)
	seen, err := c.Store.FlowMessageSeen(ctx, exporter, digest)
	if err != nil {
		return false, err
	}
	if seen {
		return false, nil
	}
	decoder := c.Decoder.Fork()
	message, err := decoder.Decode(exporter, packet)
	if err != nil {
		return false, err
	}
	if message.Skipped {
		return false, errors.New("IPFIX message contains data with missing template")
	}
	packetInfo := storage.IPFIXPacket{
		Domain: message.DomainID, Sequence: message.Sequence, RecordCount: uint32(len(message.Records)),
		ExportTime: message.ExportTime, TemplateTime: message.TemplateTime, TemplateChanged: !c.Decoder.Compatible(decoder),
	}
	if len(message.Records) > 0 {
		packetInfo.BootMS = message.Records[0].SysInitMs
		for _, record := range message.Records {
			if record.SysInitMs != packetInfo.BootMS {
				return false, errors.New("IPFIX message mixes exporter boot times")
			}
		}
	}
	if len(c.IgnoreExportTargets) > 0 {
		filtered := message.Records[:0]
		for _, record := range message.Records {
			if record.Proto == 17 && record.Src.Unmap() == exporter && c.IgnoreExportTargets[netip.AddrPortFrom(record.Dst.Unmap(), record.DstPort)] {
				continue
			}
			filtered = append(filtered, record)
		}
		message.Records = filtered
	}
	normalizer := c.Normalizer.Fork()
	flows, _ := normalizer.Normalize(exporter, received, message)
	accepted, err := c.Store.SaveIPFIXPacket(ctx, exporter, digest, received, flows, packetInfo)
	if err == nil && accepted {
		if packetInfo.BootMS != 0 {
			decoder.ForgetTemplatesBefore(exporter, packetInfo.Domain, packetInfo.BootMS)
		}
		c.Decoder = decoder
		c.Normalizer = normalizer
	}
	return accepted, err
}
func (c *Collector) Run(ctx context.Context, addr string) error {
	if len(c.Allowed) == 0 {
		return errors.New("at least one exporter must be configured")
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("IPFIX listen: %w", err)
	}
	defer conn.Close()
	log.Printf("V2 IPFIX listener active on %s", addr)
	buffer := make([]byte, 65535)
	var lastError time.Time
	for {
		if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		udp, ok := remote.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(udp.IP)
		if !ok || !c.Allowed[ip.Unmap()] {
			continue
		}
		if _, err = c.Handle(ctx, ip, time.Now(), buffer[:n]); err != nil && time.Since(lastError) > time.Minute {
			log.Printf("IPFIX ingest issue: %v", err)
			lastError = time.Now()
		}
	}
}
