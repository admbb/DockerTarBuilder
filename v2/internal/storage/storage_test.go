package storage

import (
	"context"
	"netflow-plus-v2/internal/oxidns"
	"path/filepath"
	"testing"
)

func TestEventIDConflictRollsBackPage(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	event := oxidns.Record{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.1"}
	if err = s.SavePage(ctx, "source", []oxidns.Record{event}); err != nil {
		t.Fatal(err)
	}
	event.ClientIP = "192.168.1.2"
	if err = s.SavePage(ctx, "source", []oxidns.Record{{ID: 2, CreatedAtMS: 1000, ClientIP: "192.168.1.3"}, event}); err == nil {
		t.Fatal("expected collision")
	}
	var n int
	if err = s.db.QueryRow("SELECT COUNT(*) FROM dns_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("partial page committed %d %v", n, err)
	}
}

func TestEvidenceQueryRefusesTruncatedResults(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err = s.SavePage(ctx, "source", []oxidns.Record{{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.1"}, {ID: 2, CreatedAtMS: 1500, ClientIP: "192.168.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EventsForClient(ctx, "source", "192.168.1.1", 0, 2000, 1); err == nil {
		t.Fatal("truncated evidence must fail closed")
	}
	rows, err := s.EventsForClient(ctx, "source", "192.168.1.1", 0, 2000, 2)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}
func TestRetentionUpdatesCoverageAndAggregates(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err = s.InitializeSource(ctx, "source", 1); err != nil {
		t.Fatal(err)
	}
	records := []oxidns.Record{{ID: 1, CreatedAtMS: 3600001, ClientIP: "192.168.1.1", Questions: []oxidns.Question{{Name: "old.example.com"}}}, {ID: 2, CreatedAtMS: 7200001, ClientIP: "192.168.1.1", Questions: []oxidns.Question{{Name: "new.example.com"}}}}
	if err = s.SavePage(ctx, "source", records); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteInterval(ctx, "source", 1, 10800000); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneDNSBefore(ctx, "source", 7200000); err != nil {
		t.Fatal(err)
	}
	start, end, err := s.Coverage(ctx, "source")
	if err != nil || start != 7200000 || end != 10800000 {
		t.Fatalf("coverage %d %d %v", start, end, err)
	}
	rows, err := s.DNSPopularity(ctx, "source", 0, 10800000, 10)
	if err != nil || len(rows) != 1 || rows[0].Domain != "new.example.com" {
		t.Fatalf("rows %+v %v", rows, err)
	}
}
