package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDNSCandidatesTransactionalReplacement(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "netflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.MigrateDomainIntelligence(context.Background()); err != nil {
		t.Fatal(err)
	}
	ip := "192.0.2.1"
	if err = st.Write(&Batch{DNSCandidates: map[string][]DNSName{ip: {{Name: "a.example.com", Seen: 100}, {Name: "b.example.com", Seen: 101}}}}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.LoadDNSCandidates(0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	err = st.Write(&Batch{DNSCandidates: map[string][]DNSName{ip: {{Name: "duplicate.example.com", Seen: 102}, {Name: "duplicate.example.com", Seen: 103}}}})
	if err == nil {
		t.Fatal("duplicate insert should fail")
	}
	rows, err = st.LoadDNSCandidates(0)
	if err != nil || len(rows) != 2 || rows[0].Name != "a.example.com" {
		t.Fatalf("rollback lost prior rows: %v %v", rows, err)
	}
	if err = st.Write(&Batch{DNSCandidates: map[string][]DNSName{ip: nil}}); err != nil {
		t.Fatal(err)
	}
	rows, err = st.LoadDNSCandidates(0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("delete failed: %v %v", rows, err)
	}
}
