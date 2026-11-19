package collector

import (
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/ipfix"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"testing"
	"time"
)

func TestBootIsolationAndSequenceWrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exporter := netip.MustParseAddr("192.168.1.1")
	newCollector := func() Collector {
		topo := flow.NewTopology([]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil, nil)
		return Collector{Store: db, Decoder: ipfix.NewDecoder(""), Normalizer: flow.NewNormalizer(topo, time.Minute, 2055), Allowed: map[netip.Addr]bool{exporter: true}}
	}
	c := newCollector()
	ctx := context.Background()
	received := time.Unix(7200, 0)
	check := func(packet []byte, accepted, failed bool) {
		t.Helper()
		got, err := c.Handle(ctx, exporter, received, packet)
		if got != accepted || (err != nil) != failed {
			t.Fatalf("export=%d seq=%d accepted=%v err=%v", binary.BigEndian.Uint32(packet[4:8]), binary.BigEndian.Uint32(packet[8:12]), got, err)
		}
	}

	const oldBoot = 3_000_000
	const newBoot = 4_010_000
	check(ipfixFixture(4000, 0, true), true, false)
	old := ipfixFixture(4000, 0, false, oldBoot)
	check(old, true, false)
	check(ipfixFixture(4001, math.MaxInt32, false, oldBoot+1), true, false)
	check(ipfixFixture(4002, math.MaxUint32-2, false, oldBoot), true, false)
	// The two records occupy the last index and index zero of the next cycle.
	crossing := ipfixFixture(4003, math.MaxUint32, false, oldBoot+10, oldBoot)
	check(crossing, true, false)
	check(ipfixFixture(4002, math.MaxUint32-1, false, oldBoot), true, false)
	check(ipfixFixture(4004, 0, false, oldBoot), false, true)
	check(ipfixFixture(4004, 1, false, oldBoot), true, false)
	check(ipfixFixture(4000, 2, false, oldBoot), false, true)
	check(ipfixFixture(4005, 2, false, oldBoot, newBoot), false, true)
	check(ipfixFixture(4005, 2, false, oldBoot+1, oldBoot+12), false, true)
	check(ipfixFixture(4005, 2, false, oldBoot+11), false, true)
	// A different wire boot sample must not bypass the existing sequence key.
	check(ipfixFixture(4004, 1, false, oldBoot+10), false, true)

	// The same boot/sequence state survives a process restart. The new
	// collector must wait for templates, then reject old sequence ranges.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c = newCollector()
	check(ipfixFixture(4006, 2, false, oldBoot), false, true)
	check(ipfixFixture(4006, 2, true), true, false)
	check(ipfixFixture(4006, 2, false, oldBoot-10), true, false)
	check(ipfixFixture(4010, 0, false, newBoot), false, true)
	check(ipfixFixture(4010, 0, true), true, false)
	check(ipfixFixture(4010, 0, false, newBoot), true, false)
	check(ipfixFixture(4007, 3, false, oldBoot), false, true)
	check(ipfixFixture(4009, 3, true), false, true)
	check(ipfixFixture(4011, 1, false, newBoot), true, false)
	totals, err := db.FlowTotals(ctx, received.UnixMilli(), received.Add(time.Hour).UnixMilli())
	if err != nil || totals.Records != 10 || totals.Up != 100 {
		t.Fatalf("unexpected totals %+v %v", totals, err)
	}
	received = received.Add(time.Hour)
	if err := db.PruneFlowBefore(ctx, received.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	check(old, false, false)
	check(crossing, false, false)
	totals, err = db.FlowTotals(ctx, received.UnixMilli(), received.Add(time.Hour).UnixMilli())
	if err != nil || totals.Records != 0 {
		t.Fatalf("replays changed post-retention totals %+v %v", totals, err)
	}
}

func ipfixFixture(export, sequence uint32, template bool, boots ...uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b, 10)
	binary.BigEndian.PutUint32(b[4:], export)
	binary.BigEndian.PutUint32(b[8:], sequence)
	if template {
		b = binary.BigEndian.AppendUint16(b, 2)
		b = binary.BigEndian.AppendUint16(b, 28)
		b = binary.BigEndian.AppendUint16(b, 258)
		b = binary.BigEndian.AppendUint16(b, 5)
		for _, value := range []uint16{8, 4, 12, 4, 1, 8, 14, 4, 160, 8} {
			b = binary.BigEndian.AppendUint16(b, value)
		}
	}
	if len(boots) > 0 {
		b = binary.BigEndian.AppendUint16(b, 258)
		b = binary.BigEndian.AppendUint16(b, uint16(4+28*len(boots)))
		for _, boot := range boots {
			b = append(b, 192, 168, 1, 2, 8, 8, 8, 8)
			b = binary.BigEndian.AppendUint64(b, 10)
			b = binary.BigEndian.AppendUint32(b, 1)
			b = binary.BigEndian.AppendUint64(b, boot)
		}
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func TestReplayDoesNotDoubleCount(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dgrams, err := ipfix.ReadCapture("../../testdata/captures/routeros7-ipfix-sample.bin")
	if err != nil {
		t.Fatal(err)
	}
	exporter := netip.MustParseAddr("192.168.88.1")
	topo := flow.NewTopology([]netip.Prefix{netip.MustParsePrefix("192.168.88.0/24"), netip.MustParsePrefix("fe80::/10")}, []flow.Site{{Name: "office", Prefix: netip.MustParsePrefix("192.168.99.0/24")}}, nil)
	c := Collector{Store: db, Decoder: ipfix.NewDecoder(""), Normalizer: flow.NewNormalizer(topo, time.Minute, 2055), Allowed: map[netip.Addr]bool{exporter: true}}
	for _, d := range dgrams {
		if _, err = c.Handle(context.Background(), exporter, d.Received, d.Payload); err != nil {
			t.Fatal(err)
		}
	}
	before, err := db.FlowTotals(context.Background(), 0, time.Unix(1<<35, 0).UnixMilli())
	if err != nil || before.Up+before.Down == 0 {
		t.Fatalf("first totals: %+v %v", before, err)
	}
	for _, d := range dgrams {
		inserted, err := c.Handle(context.Background(), exporter, d.Received, d.Payload)
		if err != nil || inserted {
			t.Fatalf("duplicate: %v %v", inserted, err)
		}
	}
	after, err := db.FlowTotals(context.Background(), 0, time.Unix(1<<35, 0).UnixMilli())
	if err != nil || after != before {
		t.Fatalf("totals changed: %+v %+v %v", before, after, err)
	}
}
