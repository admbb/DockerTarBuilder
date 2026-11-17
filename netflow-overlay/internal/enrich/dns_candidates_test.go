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
	n.Observe(records, now.Add(time.Hour))
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

func TestDNSCandidatesStableWithinHour(t *testing.T) {
	now := time.Unix(1700000000, 0).Truncate(time.Hour).Add(time.Minute)
	n := NewNames(100)
	records := []DNSRecord{{Type: "A", Name: "example.com", Data: "192.0.2.10"}}
	n.Observe(records, now)
	snapshot := n.CandidateRows()
	n.AckCandidateRows(snapshot)
	n.Observe(records, now.Add(time.Minute))
	if len(n.CandidateRows()) != 0 {
		t.Fatal("unchanged observations must not trigger repeated writes")
	}
	n.Observe(records, now.Add(time.Hour))
	if len(n.CandidateRows()) != 1 {
		t.Fatal("new observation bucket must be persisted")
	}
}

func TestEvictionPreservesAmbiguity(t *testing.T) {
	now := time.Now()
	n := NewNames(1)
	ip := netip.MustParseAddr("192.0.2.9")
	var records []DNSRecord
	for i := 0; i <= candidateLimit; i++ {
		records = append(records, DNSRecord{Type: "A", Name: fmt.Sprintf("n%d.example.com", i), Data: ip.String()})
	}
	n.Observe(records, now)
	n.Observe([]DNSRecord{{Type: "A", Name: "elsewhere.example.com", Data: "192.0.2.8"}}, now.Add(time.Second))
	n.Observe([]DNSRecord{{Type: "A", Name: "n0.example.com", Data: ip.String()}}, now.Add(2*time.Second))
	if _, incomplete := n.Candidates(ip, now); !incomplete {
		t.Fatal("legacy eviction lost ambiguity")
	}
	copy := NewNames(10)
	for _, row := range n.CandidateRows()[ip.String()] {
		copy.RestoreCandidate(row, now)
	}
	if _, incomplete := copy.Candidates(ip, now); !incomplete {
		t.Fatal("persisted ambiguity was lost")
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

func TestCandidateCapacitySaturationSurvivesRestart(t *testing.T) {
	now := time.Now()
	n := NewNames(1)
	n.Observe([]DNSRecord{{Type: "A", Name: "one.example.com", Data: "192.0.2.1"}, {Type: "A", Name: "two.example.com", Data: "192.0.2.2"}}, now)
	ip := netip.MustParseAddr("192.0.2.1")
	if _, incomplete := n.Candidates(ip, now); !incomplete {
		t.Fatal("capacity loss must fail closed")
	}
	rows := n.CandidateRows()
	if len(rows["*"]) != 1 {
		t.Fatal("missing persisted saturation marker")
	}
	restored := NewNames(1)
	for _, group := range rows {
		for _, row := range group {
			restored.RestoreCandidate(row, now)
		}
	}
	if _, incomplete := restored.Candidates(ip, now); !incomplete {
		t.Fatal("restart lost saturation evidence")
	}
}
