package correlation

import (
	"testing"
	"time"
)

func TestCorrelationSafety(t *testing.T) {
	at := time.Unix(1000, 0)
	f := Flow{ClientIP: "192.168.1.10", RemoteIP: "8.8.8.8", Start: at.Add(20 * time.Second)}
	event := DNSEvent{ID: 1, ClientIP: f.ClientIP, At: at, ResponseOK: true, Questions: []Question{{Name: "video.example.com.", Type: "A"}}, Answers: []Answer{{Name: "video.example.com", Type: "CNAME", Data: "edge.example.net", TTL: 30}, {Name: "edge.example.net", Type: "A", Data: f.RemoteIP, TTL: 300}}}
	rules := []Rule{{Domain: "example.com", AppID: "video"}}
	if got := Match(f, []DNSEvent{event}, rules, 60*time.Second); got.AppID != "video" {
		t.Fatalf("CNAME match: %+v", got)
	}
	other := event
	other.ID = 2
	other.Questions = []Question{{Name: "other.example.org", Type: "A"}}
	other.Answers = []Answer{{Name: "other.example.org", Type: "A", Data: f.RemoteIP, TTL: 300}}
	if got := Match(f, []DNSEvent{event, other}, rules, 60*time.Second); got.AppID != "" || got.Reason != "ambiguous_or_unknown" {
		t.Fatalf("shared IP: %+v", got)
	}
	other.ClientIP = "192.168.1.11"
	if got := Match(f, []DNSEvent{event, other}, rules, 60*time.Second); got.AppID != "video" {
		t.Fatalf("client separation: %+v", got)
	}
	f.Start = at.Add(31 * time.Second)
	if got := Match(f, []DNSEvent{event}, rules, 60*time.Second); got.AppID != "" {
		t.Fatalf("CNAME TTL ignored: %+v", got)
	}
	f.Start = at.Add(-time.Second)
	if got := Match(f, []DNSEvent{event}, rules, 60*time.Second); got.AppID != "" {
		t.Fatalf("future DNS: %+v", got)
	}
}
func TestConflictingRulesAndStrictWindow(t *testing.T) {
	at := time.Unix(1000, 0)
	ev := DNSEvent{ID: 1, ClientIP: "192.168.1.1", At: at, ResponseOK: true, Questions: []Question{{Name: "a.example.com"}}, Answers: []Answer{{Name: "a.example.com", Type: "A", Data: "8.8.4.4", TTL: 60}}}
	f := Flow{ClientIP: ev.ClientIP, RemoteIP: "8.8.4.4", Start: at.Add(time.Second)}
	rules := []Rule{{Domain: "example.com", AppID: "a"}, {Domain: "example.com", AppID: "b"}}
	if got := Match(f, []DNSEvent{ev}, rules, 60*time.Second); got.AppID != "" {
		t.Fatalf("conflicting rules: %+v", got)
	}
	if got := Match(f, []DNSEvent{ev}, rules, 45*time.Second); got.Reason != "invalid_window" {
		t.Fatalf("window: %+v", got)
	}
}

func TestMatchIntervalRejectsConflictDuringSegment(t *testing.T) {
	at := time.Unix(2000, 0)
	f := Flow{ClientIP: "192.168.1.10", RemoteIP: "8.8.8.8", Start: at}
	ev := DNSEvent{
		ID: 1, ClientIP: f.ClientIP, At: at.Add(-time.Second), ResponseOK: true,
		Questions: []Question{{Name: "a.example", Type: "A"}},
		Answers:   []Answer{{Name: "a.example", Type: "A", Data: f.RemoteIP, TTL: 20}},
	}
	conflict := DNSEvent{
		ID: 2, ClientIP: f.ClientIP, At: at.Add(time.Second), ResponseOK: true,
		Questions: []Question{{Name: "b.example", Type: "A"}},
		Answers:   []Answer{{Name: "b.example", Type: "A", Data: f.RemoteIP, TTL: 1}},
	}
	rules := []Rule{{Domain: "a.example", AppID: "a"}, {Domain: "b.example", AppID: "b"}}
	end := at.Add(5 * time.Second)
	if got := MatchInterval(f, end, []DNSEvent{ev, conflict}, rules, 60*time.Second); got.AppID != "" || got.Reason != "ambiguous_or_unknown" {
		t.Fatalf("overlapping conflicting DNS answer must veto: %+v", got)
	}
	later := ev
	later.At = at.Add(time.Second)
	if got := MatchInterval(f, end, []DNSEvent{later}, rules, 60*time.Second); got.AppID != "" || got.Reason != "dns_segment_not_covered" {
		t.Fatalf("later DNS response cannot cover earlier bytes: %+v", got)
	}
}

func TestConflictingTTLUsesShortestAndMalformedChainCannotAuthorize(t *testing.T) {
	at := time.Unix(2000, 0)
	f := Flow{ClientIP: "192.168.1.10", RemoteIP: "8.8.8.8", Start: at.Add(time.Second)}
	ev := DNSEvent{
		ID: 1, ClientIP: f.ClientIP, At: at, ResponseOK: true,
		Questions: []Question{{Name: "a.example", Type: "A"}},
		Answers: []Answer{
			{Name: "a.example", Type: "CNAME", Data: "edge.example", TTL: 20},
			{Name: "a.example", Type: "CNAME", Data: "edge.example", TTL: 2},
			{Name: "edge.example", Type: "A", Data: f.RemoteIP, TTL: 20},
		},
	}
	rules := []Rule{{Domain: "a.example", AppID: "a"}}
	if got := MatchInterval(f, at.Add(3*time.Second), []DNSEvent{ev}, rules, 60*time.Second); got.Reason != "dns_segment_not_covered" {
		t.Fatalf("later duplicate must not extend the shorter TTL: %+v", got)
	}
	ev.Answers[1].Data = "other.example"
	if got := Match(f, []DNSEvent{ev}, rules, 60*time.Second); got.Reason != "ambiguous_or_unknown" {
		t.Fatalf("multiple CNAME targets cannot establish attribution: %+v", got)
	}
}

func TestClockUncertaintyRequiresTemporalMarginAroundFlow(t *testing.T) {
	at := time.Unix(2100, 0)
	f := Flow{ClientIP: "192.168.1.10", RemoteIP: "8.8.8.8", Start: at}
	ev := DNSEvent{
		ID: 1, ClientIP: f.ClientIP, At: at.Add(-time.Second), ResponseOK: true,
		Questions: []Question{{Name: "a.example", Type: "A"}},
		Answers:   []Answer{{Name: "a.example", Type: "A", Data: f.RemoteIP, TTL: 30}},
	}
	rules := []Rule{{Domain: "a.example", AppID: "a"}}
	end := at.Add(time.Second)
	if got := MatchUncertainInterval(f, end, []DNSEvent{ev}, rules, 60*time.Second, 2*time.Second); got.Reason != "dns_segment_not_covered" {
		t.Fatalf("response inside start margin: %+v", got)
	}
	ev.At = at.Add(-10 * time.Second)
	ev.Answers[0].TTL = 12
	if got := MatchUncertainInterval(f, end, []DNSEvent{ev}, rules, 60*time.Second, 2*time.Second); got.Reason != "dns_segment_not_covered" {
		t.Fatalf("expiry inside end margin: %+v", got)
	}
	ev.Answers[0].TTL = 30
	if got := MatchUncertainInterval(f, end, []DNSEvent{ev}, rules, 60*time.Second, 2*time.Second); got.AppID != "a" {
		t.Fatalf("sufficient margin: %+v", got)
	}
}
