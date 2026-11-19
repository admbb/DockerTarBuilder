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
	if end.Before(f.Start) {
		return Result{Reason: "invalid_flow_interval"}
	}
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
		if e != nil || ip.Unmap() != client || !ev.ResponseOK || len(ev.Questions) != 1 || ev.At.After(end) || f.Start.Sub(ev.At) > window {
			continue
		}
		q := domain(ev.Questions[0].Name)
		if q == "" {
			continue
		}
		type node struct {
			name    string
			expires time.Time
		}
		queue := []node{{q, ev.At.Add(window)}}
		visited := map[string]bool{}
		matched := false
		covers := false
		for len(queue) > 0 && len(visited) < 32 {
			n := queue[0]
			queue = queue[1:]
			if visited[n.name] {
				continue
			}
			visited[n.name] = true
			for _, a := range ev.Answers {
				if domain(a.Name) != n.name || a.TTL == 0 {
					continue
				}
				expires := ev.At.Add(time.Duration(a.TTL) * time.Second)
				if expires.After(n.expires) {
					expires = n.expires
				}
				if !f.Start.Before(expires) {
					continue
				}
				switch strings.ToUpper(a.Type) {
				case "CNAME":
					target := domain(a.Data)
					if target != "" && !visited[target] {
						queue = append(queue, node{target, expires})
					}
				case "A", "AAAA":
					ip, e := netip.ParseAddr(a.Data)
					if e == nil && ip.Unmap() == remote {
						matched = true
						covers = covers || (!ev.At.After(f.Start) && end.Before(expires))
					}
				}
			}
		}
		if !matched {
			continue
		}
		covered = covered || covers
		names[q] = true
		ids = append(ids, ev.ID)
		app, ok := lookup(rules, q)
		if !ok {
			unknown = true
		} else if selected != "" && selected != app {
			unknown = true
		} else {
			selected = app
		}
	}
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
