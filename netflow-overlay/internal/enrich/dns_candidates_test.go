package enrich

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestDNSCandidatesAliasesRestoreAndAcknowledgement(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	n := NewNames(100)
	records := []DNSRecord{{Type: "A", Name: "edge.example.net", Data: "192.0.2.1"}, {Type: "CNAME", Name: "one.example.com", Data: "edge.example.net"}, {Type: "CNAME", Name: "two.example.com", Data: "edge.example.net"}}
	n.Observe(records, now)
	ip := netip.MustParseAddr("192.0.2.1")
	names, incomplete := n.Candidates(ip, now)
	if incomplete || len(names) != 3 {
		t.Fatalf("names=%v incomplete=%v", names, incomplete)
	}
	snapshot := n.CandidateRows()
	n.Observe(records, now.Add(time.Second))
	n.AckCandidateRows(snapshot)
	if len(n.CandidateRows()) != 1 {
		t.Fatal("new observation was acknowledged by old snapshot")
	}
	snapshot = n.CandidateRows()
	restored := NewNames(100)
	for _, row := range snapshot[ip.String()] {
		restored.RestoreCandidate(row, now)
	}
	got, incomplete := restored.Candidates(ip, now)
	if incomplete || len(got) != 3 {
		t.Fatalf("restored=%v incomplete=%v", got, incomplete)
	}
	n.AckCandidateRows(snapshot)
	if len(n.CandidateRows()) != 0 {
		t.Fatal("saved snapshot remains dirty")
	}
}

func TestDNSCandidatesOverflowIsConservative(t *testing.T) {
	now := time.Now()
	n := NewNames(100)
	var records []DNSRecord
	for i := 0; i < candidateLimit+1; i++ {
		records = append(records, DNSRecord{Type: "A", Name: fmt.Sprintf("n%d.example.com", i), Data: "192.0.2.9"})
	}
	n.Observe(records, now)
	ip := netip.MustParseAddr("192.0.2.9")
	_, incomplete := n.Candidates(ip, now)
	if !incomplete {
		t.Fatal("overflow must be treated as incomplete")
	}
	restored := NewNames(100)
	for _, row := range n.CandidateRows()[ip.String()] {
		restored.RestoreCandidate(row, now)
	}
	_, incomplete = restored.Candidates(ip, now)
	if !incomplete {
		t.Fatal("restored overflow must remain incomplete")
	}
}
