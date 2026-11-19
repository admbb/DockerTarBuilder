package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"netflow-plus-v2/internal/oxidns"
)

func TestDNSAnswerIndexResumesBackfillAndPreservesLiveHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	_, err = legacy.Exec(`CREATE TABLE dns_events(source TEXT NOT NULL, event_id INTEGER NOT NULL, created_ms INTEGER NOT NULL, client_ip TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(source,event_id)) WITHOUT ROWID`)
	if err != nil {
		t.Fatal(err)
	}
	const client = "192.168.1.2"
	answers := []oxidns.Answer{
		{Type: "a", Data: "192.0.2.1", TTL: 20},
		{Type: "A", Data: "192.0.2.1", TTL: 90},
		{Type: "AAAA", Data: "2001:0DB8::01", TTL: 90},
	}
	record := oxidns.Record{ID: 1, CreatedAtMS: 3601000, ClientIP: client, Answers: answers}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO dns_events VALUES('dns',1,3601000,?,?)`, client, string(payload)); err != nil {
		t.Fatal(err)
	}
	if err := initDNSAnswerIndex(legacy); err != nil {
		t.Fatal(err)
	}
	// Commit just one migration batch before shutdown.
	interrupted := &Store{db: legacy}
	if done, err := interrupted.backfillDNSAnswerBatch(ctx); done || err != nil {
		t.Fatalf("first batch complete=%v: %v", done, err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		ready, err := db.DNSAnswerIndexReady(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS address index did not resume")
		}
		time.Sleep(10 * time.Millisecond)
	}
	record.ID, record.CreatedAtMS = 2, 3660000
	if err := db.SavePage(ctx, "dns", []oxidns.Record{record}); err != nil {
		t.Fatal(err)
	}
	batch, err := db.DNSCorrelationBatch(ctx, "dns", []DNSCorrelationQuery{
		{client, "192.0.2.1", 3650000, 3670000, 3680000},
		{client, "2001:db8::1", 3650000, 3670000, 3680000},
		{client, "192.0.2.99", 3650000, 3670000, 3680000},
		{client, "192.0.2.1", 3650000, 3691000, 3700000},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch[0]) != 2 || len(batch[1]) != 2 || len(batch[2]) != 0 || batch[2] == nil || len(batch[3]) != 1 || batch[3][0].ID != 2 {
		t.Fatalf("unexpected evidence: %+v", batch)
	}
	if err := db.CompleteInterval(ctx, "dns", 0, 7200000); err != nil {
		t.Fatal(err)
	}
	if err := db.PruneDNSBefore(ctx, "dns", 7200000); err != nil {
		t.Fatal(err)
	}
	var indexed int
	if err := db.db.QueryRow(`SELECT count(*) FROM dns_answer_index`).Scan(&indexed); err != nil || indexed != 0 {
		t.Fatalf("retained answer index rows: %d, %v", indexed, err)
	}
}

func TestDNSCorrelationBatchKeepsEvidenceLimitForNonmatchingAnswers(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const client = "192.168.1.2"
	_, err = db.db.Exec(`WITH RECURSIVE ids(i) AS (
		SELECT 1 UNION ALL SELECT i+1 FROM ids WHERE i<10001
	) INSERT INTO dns_events SELECT 'dns',i,1000,?,json_object('id',i,'created_at_ms',1000,'client_ip',?) FROM ids`, client, client)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := db.DNSCorrelationBatch(context.Background(), "dns", []DNSCorrelationQuery{
		{client, "192.0.2.1", 1000, 1001, 1100},
		{client, "192.0.2.1", 1001, 1001, 1100},
	})
	if err != nil || batch[0] != nil || batch[1] == nil || len(batch[1]) != 0 {
		t.Fatalf("wrong evidence limit: %v, %v", batch, err)
	}
}

func TestDNSCorrelationBatchKeepsConservativeIPv6HistoryLimit(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const client = "192.168.1.2"
	_, err = db.db.Exec(`WITH RECURSIVE ids(i) AS (
		SELECT 1 UNION ALL SELECT i+1 FROM ids WHERE i<10001
	) INSERT INTO dns_events SELECT 'dns',i,1000,?,
		json_object('id',i,'created_at_ms',1000,'client_ip',?,
		            'answers_json',json_array(json_object('rr_type','AAAA','payload_text','2001:db8::10','ttl',15)))
	FROM ids`, client, client)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := db.DNSCorrelationBatch(context.Background(), "dns", []DNSCorrelationQuery{
		{client, "2001:db8::20", 1001, 1001, 1100},
		{client, "192.0.2.1", 1001, 1001, 1100},
		{client, "2001:db8::20", 16000, 16000, 16100},
	})
	if err != nil || batch[0] != nil || batch[1] == nil || len(batch[1]) != 0 || batch[2] == nil || len(batch[2]) != 0 {
		t.Fatalf("wrong historical evidence limit: %v, %v", batch, err)
	}
}
