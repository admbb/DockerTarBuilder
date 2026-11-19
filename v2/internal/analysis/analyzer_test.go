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

func TestAnalyzeRequiresCompleteEvidence(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	f := correlation.Flow{ClientIP: "192.168.1.2", RemoteIP: "8.8.8.8", Start: time.UnixMilli(2000)}
	a := Analyzer{Store: db, Source: "s", Window: 30 * time.Second, Rules: []correlation.Rule{{Domain: "example.com", AppID: "example"}}, EvidenceComplete: true}
	got, err := a.Analyze(ctx, f)
	if err != nil || got.Reason != "dns_sync_incomplete" {
		t.Fatalf("got %+v %v", got, err)
	}
	event := oxidns.Record{ID: 1, CreatedAtMS: 1000, ClientIP: f.ClientIP, HasResponse: true, RCode: "No Error", Questions: []oxidns.Question{{Name: "www.example.com", QType: "A"}}, Answers: []oxidns.Answer{{Name: "www.example.com", Type: "A", Data: f.RemoteIP, TTL: 30}}}
	if err = db.SavePage(ctx, "s", []oxidns.Record{event}); err != nil {
		t.Fatal(err)
	}
	if err = db.CompleteInterval(ctx, "s", 0, 3000); err != nil {
		t.Fatal(err)
	}
	a.EvidenceComplete = false
	if incomplete, err := a.Analyze(ctx, f); err != nil || incomplete.Reason != "dns_completeness_unverified" {
		t.Fatalf("unverified source: %+v %v", incomplete, err)
	}
	a.EvidenceComplete = true
	got, err = a.Analyze(ctx, f)
	if err != nil || got.AppID != "example" {
		t.Fatalf("got %+v %v", got, err)
	}
}
