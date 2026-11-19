package storage

import (
	"context"
	"netflow-plus-v2/internal/oxidns"
	"path/filepath"
	"testing"
)

func TestDNSPopularityCountsQueriesNotBytes(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	records := []oxidns.Record{{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.2", Questions: []oxidns.Question{{Name: "Example.com."}, {Name: "example.com"}}}, {ID: 2, CreatedAtMS: 2000, ClientIP: "192.168.1.3", Questions: []oxidns.Question{{Name: "example.com"}}}}
	if err = s.SavePage(ctx, "x", records); err != nil {
		t.Fatal(err)
	}
	if err = s.SavePage(ctx, "x", records); err != nil {
		t.Fatal(err)
	}
	got, err := s.DNSPopularity(ctx, "x", 0, 3000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Queries != 2 || got[0].Devices != 2 {
		t.Fatalf("got %+v", got)
	}
}
