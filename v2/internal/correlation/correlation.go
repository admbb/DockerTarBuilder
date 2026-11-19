// Package correlation links recorded DNS responses to flow starts without
// treating DNS query counts as traffic measurements.
package correlation

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Rule struct {
	Domain, AppID  string
	Exact, Exclude bool
	Priority       int
}
type Question struct{ Name, Type string }
type Answer struct {
	Name, Type, Data string
	TTL              uint32
}
type DNSEvent struct {
	ID         int64
	ClientIP   string
	At         time.Time
	ResponseOK bool
	Questions  []Question
	Answers    []Answer
}
type Flow struct {
	ClientIP, RemoteIP string
	Start              time.Time
}
type Result struct {
	AppID, Reason string
	Domains       []string
	EventIDs      []int64
}

func domain(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }
func lookup(rules []Rule, name string) (string, bool) {
	name = domain(name)
	bestPriority, bestLength := -int(^uint(0)>>1)-1, -1
	bestApp := ""
	bestExclude := false
	bestExact := false
	ambiguous := false
	for _, r := range rules {
		d := domain(r.Domain)
		if d == "" || (!r.Exact && name != d && !strings.HasSuffix(name, "."+d)) || (r.Exact && name != d) {
			continue
		}
		if r.Priority > bestPriority || (r.Priority == bestPriority && (len(d) > bestLength || (len(d) == bestLength && r.Exact && !bestExact))) {
			bestPriority, bestLength = r.Priority, len(d)
			bestApp, bestExclude, bestExact, ambiguous = r.AppID, r.Exclude, r.Exact, false
		} else if r.Priority == bestPriority && len(d) == bestLength && r.Exact == bestExact && (bestApp != r.AppID || bestExclude != r.Exclude) {
			ambiguous = true
		}
	}
	if ambiguous || bestExclude || bestApp == "" {
		return "", false
	}
	return bestApp, true
}

// MatchDomain classifies a name for query popularity only. It is not evidence
// that any bytes belong to the matched application.
func MatchDomain(rules []Rule, name string) (string, bool) { return lookup(rules, name) }

// Match returns an attribution only if every applicable DNS observation for
// this client and address agrees on an application. A and AAAA answers must
// be reached through the question's CNAME chain. TTL 0 never authorizes a
// later flow. The caller must not assume accumulated connection bytes fall
// within the matching interval.
func Match(f Flow, events []DNSEvent, rules []Rule, window time.Duration) Result {
	return MatchInterval(f, f.Start, events, rules, window)
}

// MatchInterval requires an agreeing answer to remain valid for the whole
// observed segment. A later answer may expose ambiguity, but cannot justify
// bytes that preceded the answer.
func MatchInterval(f Flow, end time.Time, events []DNSEvent, rules []Rule, window time.Duration) Result {
	return MatchUncertainInterval(f, end, events, rules, window, 0)
}

// MatchUncertainInterval requires the evidence to hold for every possible
// segment interval inside the exporter timestamp uncertainty.
func MatchUncertainInterval(f Flow, end time.Time, events []DNSEvent, rules []Rule, window, uncertainty time.Duration) Result {
	if end.Before(f.Start) || uncertainty < 0 {
		return Result{Reason: "invalid_flow_interval"}
	}
	earliestStart := f.Start.Add(-uncertainty)
	latestStart := f.Start.Add(uncertainty)
	end = end.Add(uncertainty)
	if window != 30*time.Second && window != 60*time.Second && window != 120*time.Second {
		return Result{Reason: "invalid_window"}
	}
	client, err := netip.ParseAddr(f.ClientIP)
	if err != nil {
		return Result{Reason: "invalid_client"}
	}
	client = client.Unmap()
	remote, err := netip.ParseAddr(f.RemoteIP)
	if err != nil || !remote.IsGlobalUnicast() {
		return Result{Reason: "invalid_remote"}
	}
	remote = remote.Unmap()
	names := map[string]bool{}
	var ids []int64
	selected := ""
	unknown := false
	covered := false
	for _, ev := range events {
		ip, e := netip.ParseAddr(ev.ClientIP)
		if e != nil || ip.Unmap() != client || !ev.ResponseOK || ev.At.After(end) {
			continue
		}
		matchedEvent := false
		for _, question := range ev.Questions {
			q := domain(question.Name)
			if q == "" {
				continue
			}
			expires, ambiguous := answerExpiry(ev, q, question.Type, remote)
			if !earliestStart.Before(expires) {
				continue
			}
			matchedEvent = true
			names[q] = true
			covered = covered || (!ambiguous && len(ev.Questions) == 1 && ev.At.Before(earliestStart) &&
				end.Before(expires) && latestStart.Before(ev.At.Add(window)))
			app, ok := lookup(rules, q)
			if ambiguous || len(ev.Questions) != 1 || !ok || (selected != "" && selected != app) {
				unknown = true
			} else {
				selected = app
			}
		}
		if matchedEvent {
			ids = append(ids, ev.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	domains := make([]string, 0, len(names))
	for n := range names {
		domains = append(domains, n)
	}
	sort.Strings(domains)
	if len(domains) == 0 {
		return Result{Reason: "no_matching_dns"}
	}
	if unknown || selected == "" {
		return Result{Reason: "ambiguous_or_unknown", Domains: domains, EventIDs: ids}
	}
	if !covered {
		return Result{Reason: "dns_segment_not_covered", Domains: domains, EventIDs: ids}
	}
	return Result{AppID: selected, Reason: "dns_client_ip_ttl", Domains: domains, EventIDs: ids}
}

// answerExpiry follows a single CNAME chain. A malformed chain can veto a
// match when its response mentions the remote address, but cannot support one.
func answerExpiry(ev DNSEvent, name, qtype string, remote netip.Addr) (time.Time, bool) {
	qtype = strings.ToUpper(qtype)
	var expiry time.Time
	visited := make(map[string]bool)
	for name != "" && len(visited) < 32 && !visited[name] {
		visited[name] = true
		target := ""
		targetExpiry := expiry
		var addressExpiry time.Time
		hasAddress := false
		for _, answer := range ev.Answers {
			if domain(answer.Name) != name {
				continue
			}
			rrtype := strings.ToUpper(answer.Type)
			until := ev.At.Add(time.Duration(answer.TTL) * time.Second)
			if !expiry.IsZero() && expiry.Before(until) {
				until = expiry
			}
			switch rrtype {
			case "CNAME":
				next := domain(answer.Data)
				if next == "" || (target != "" && target != next) {
					return malformedExpiry(ev, remote), true
				}
				target = next
				if targetExpiry.IsZero() || until.Before(targetExpiry) {
					targetExpiry = until
				}
			case "A", "AAAA":
				hasAddress = true
				if matchesAddress(answer, remote) && (qtype == "" || qtype == "ANY" || qtype == rrtype) {
					if addressExpiry.IsZero() || until.Before(addressExpiry) {
						addressExpiry = until
					}
				}
			}
		}
		if target == "" {
			return addressExpiry, false
		}
		if hasAddress {
			return malformedExpiry(ev, remote), true
		}
		name, expiry = target, targetExpiry
	}
	return malformedExpiry(ev, remote), true
}

func matchesAddress(answer Answer, remote netip.Addr) bool {
	ip, err := netip.ParseAddr(answer.Data)
	if err != nil || ip.Unmap() != remote {
		return false
	}
	switch strings.ToUpper(answer.Type) {
	case "A":
		return ip.Is4()
	case "AAAA":
		return ip.Is6() && !ip.Is4In6()
	default:
		return false
	}
}

func malformedExpiry(ev DNSEvent, remote netip.Addr) time.Time {
	var latest time.Time
	for _, answer := range ev.Answers {
		if matchesAddress(answer, remote) {
			until := ev.At.Add(time.Duration(answer.TTL) * time.Second)
			if until.After(latest) {
				latest = until
			}
		}
	}
	return latest
}
