package analysis

import (
	"context"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"testing"
	"time"
)

func TestAnalyzeRequiresRescannedEvidence(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	f := correlation.Flow{ClientIP: "192.168.1.2", RemoteIP: "8.8.8.8", Start: time.UnixMilli(2000)}
	a := Analyzer{Store: db, Source: "s", Window: 30 * time.Second, Rules: []correlation.Rule{{Domain: "example.com", AppID: "example"}}}
	got, err := a.Analyze(ctx, f)
	if err != nil || got.Reason != "dns_rescan_pending" {
		t.Fatalf("got %+v %v", got, err)
	}
	event := oxidns.Record{ID: 1, CreatedAtMS: 1000, ClientIP: f.ClientIP, HasResponse: true, RCode: "No Error", Questions: []oxidns.Question{{Name: "www.example.com", QType: "A"}}, Answers: []oxidns.Answer{{Name: "www.example.com", Type: "A", Data: f.RemoteIP, TTL: 30}}}
	if err = db.SavePage(ctx, "s", []oxidns.Record{event}); err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteDNSScan(ctx, "s", 0, 0, 3000, 3000, 1000); err != nil {
		t.Fatal(err)
	}
	if incomplete, err := a.Analyze(ctx, f); err != nil || incomplete.Reason != "dns_rescan_pending" {
		t.Fatalf("single scan: %+v %v", incomplete, err)
	}
	if err = db.CompleteDNSScan(ctx, "s", 3000, 0, 4000, 4000, 1000); err != nil {
		t.Fatal(err)
	}
	got, err = a.Analyze(ctx, f)
	if err != nil || got.AppID != "example" {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestOlderRetainedAnswerVetoesNewNameWhileTTLIsLive(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	f := correlation.Flow{ClientIP: "192.168.1.2", RemoteIP: "8.8.8.8", Start: time.UnixMilli(100000)}
	a := Analyzer{Store: db, Source: "s", Window: 60 * time.Second, Rules: []correlation.Rule{
		{Domain: "a.example", AppID: "a"}, {Domain: "b.example", AppID: "b"},
	}}
	newEvent := func(id, at int64, name string, ttl uint32) oxidns.Record {
		return oxidns.Record{ID: id, CreatedAtMS: at, ClientIP: f.ClientIP, HasResponse: true, RCode: "NOERROR",
			Questions: []oxidns.Question{{Name: name, QType: "A"}},
			Answers:   []oxidns.Answer{{Name: name, Type: "A", Data: f.RemoteIP, TTL: ttl}}}
	}
	if err := db.SavePage(ctx, "s", []oxidns.Record{newEvent(1, 30000, "b.example", 300), newEvent(2, 95000, "a.example", 30)}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteInterval(ctx, "s", 0, 50000); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDNSScan(ctx, "s", 50000, 40000, 120000, 120000, 1000); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDNSScan(ctx, "s", 120000, 40000, 130000, 130000, 1000); err != nil {
		t.Fatal(err)
	}
	got, err := a.Analyze(ctx, f)
	if err != nil || got.AppID != "" || got.Reason != "ambiguous_or_unknown" || len(got.EventIDs) != 2 {
		t.Fatalf("older live answer must veto: %+v, %v", got, err)
	}
	status, err := db.DNSStability(ctx, "s")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := a.AnalyzeBatch(ctx, []Interval{{Flow: f, End: f.Start}}, status)
	if err != nil || len(batch) != 1 || batch[0].AppID != "" || batch[0].Reason != "ambiguous_or_unknown" || len(batch[0].EventIDs) != 2 {
		t.Fatalf("batched evidence must preserve the historical veto: %+v, %v", batch, err)
	}
}
