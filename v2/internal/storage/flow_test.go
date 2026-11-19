package storage

import (
	"context"
	"crypto/sha256"
	"math"
	"net/netip"
	"netflow-plus-v2/internal/flow"
	"path/filepath"
	"testing"
	"time"
)

func TestFlowMessageDedupAndAtomicCounters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(7200, 0)
	exporter := netip.MustParseAddr("192.168.1.1")
	ip := netip.MustParseAddr("192.168.1.2")
	digest := sha256.Sum256([]byte("message"))
	remote := netip.MustParseAddr("8.8.8.8")
	rows := []flow.Flow{{LocalIP: ip, RemoteIP: remote, Zone: flow.ZoneWAN, Dir: flow.Up, Bytes: 100}, {LocalIP: ip, RemoteIP: remote, Zone: flow.ZoneWAN, Dir: flow.Down, Bytes: 200}}
	inserted, err := s.SaveFlowMessage(ctx, exporter, digest, now, rows, 1, 10, 2)
	if err != nil || !inserted {
		t.Fatalf("insert %v %v", inserted, err)
	}
	inserted, err = s.SaveFlowMessage(ctx, exporter, digest, now, rows, 1, 10, 2)
	if err != nil || inserted {
		t.Fatalf("duplicate %v %v", inserted, err)
	}
	conflict := sha256.Sum256([]byte("same sequence, different content"))
	if _, err = s.SaveFlowMessage(ctx, exporter, conflict, now, rows, 1, 10, 2); err == nil {
		t.Fatal("sequence conflict must fail closed")
	}
	overlap := sha256.Sum256([]byte("partially overlapping sequence"))
	if _, err = s.SaveFlowMessage(ctx, exporter, overlap, now, rows, 1, 11, 2); err == nil {
		t.Fatal("overlapping sequence must fail closed")
	}
	total, err := s.FlowTotals(ctx, 0, now.Add(time.Hour).UnixMilli())
	if err != nil || total.Up != 100 || total.Down != 200 || total.Records != 2 {
		t.Fatalf("totals %+v %v", total, err)
	}
	bad := sha256.Sum256([]byte("bad"))
	if _, err = s.SaveFlowMessage(ctx, exporter, bad, now, []flow.Flow{{LocalIP: ip, Bytes: math.MaxUint64}}, 1, 12, 1); err == nil {
		t.Fatal("accepted overflow")
	}
	var n int
	if err = s.db.QueryRow("SELECT count(*) FROM flow_messages").Scan(&n); err != nil || n != 1 {
		t.Fatalf("failed message not rolled back: %d %v", n, err)
	}
	if err = s.PruneFlowBefore(ctx, now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	inserted, err = s.SaveFlowMessage(ctx, exporter, digest, now, rows, 1, 10, 2)
	if err != nil || inserted {
		t.Fatalf("pruned replay accepted: %v %v", inserted, err)
	}
}

func TestIPFIXSessionPreservesExistingSequenceLedger(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(7200, 0)
	exporter := netip.MustParseAddr("192.168.1.1")
	oldDigest := sha256.Sum256([]byte("original data"))
	if ok, err := s.SaveFlowMessage(ctx, exporter, oldDigest, now, nil, 1, 10, 2); err != nil || !ok {
		t.Fatalf("legacy insert: %v %v", ok, err)
	}
	save := func(label string, boot uint64, ts, seq uint32, accept, failed bool) {
		t.Helper()
		ok, err := s.SaveIPFIXPacket(ctx, exporter, sha256.Sum256([]byte(label)), now, nil,
			IPFIXPacket{Domain: 1, Sequence: seq, RecordCount: 1, BootMS: boot, ExportTime: ts, TemplateTime: ts})
		if ok != accept || (err != nil) != failed {
			t.Fatalf("%s: accepted=%v err=%v", label, ok, err)
		}
	}
	save("first-observed boot novel data", 1_000_000, 4000, 12, true, false)
	save("legacy partial overlap", 1_000_000, 3999, 11, false, true)
	save("original data", 1_000_000, 3999, 10, false, false)
	save("new confirmed boot reused sequence", 4_002_000, 4002, 10, true, false)
	save("retired boot delayed data", 1_000_000, 4001, 13, false, true)
}
