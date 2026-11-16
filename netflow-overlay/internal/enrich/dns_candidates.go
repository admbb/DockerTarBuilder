package enrich

import (
	"net/netip"
	"sort"
	"time"
)

// DNS cache records do not link a client query to a connection. Keep bounded
// candidates and fail closed when a shared address has too many names.
const candidateLimit = 16
const candidateTTL = 24 * time.Hour

type candidateEntry struct {
	names    map[string]int64
	overflow int64
	dirty    bool
}

type DNSCandidate struct {
	IP     string
	Domain string
	Seen   int64
}

// observeCandidates is called with n.mu held; the old single-name view remains
// unchanged. CNAMEs can have multiple aliases and cycles; traversal is bounded.
func (n *Names) observeCandidates(records []DNSRecord, now time.Time) {
	aliases := map[string][]string{}
	for _, r := range records {
		if r.Type == "CNAME" {
			target, targetErr := NormalizeDomain(r.Data)
			alias, aliasErr := NormalizeDomain(r.Name)
			if targetErr == nil && aliasErr == nil {
				aliases[target] = append(aliases[target], alias)
			}
		}
	}
	ts := now.Unix()
	for _, r := range records {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		ip, err := netip.ParseAddr(r.Data)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		base, err := NormalizeDomain(r.Name)
		if err != nil {
			continue
		}
		e := n.candidates[ip]
		if e == nil {
			e = &candidateEntry{names: map[string]int64{}}
			n.candidates[ip] = e
		}
		queue := []string{base}
		visited := map[string]bool{}
		for len(queue) > 0 {
			name := queue[0]
			queue = queue[1:]
			if visited[name] {
				continue
			}
			visited[name] = true
			if len(visited) > candidateLimit {
				e.overflow = ts
				e.dirty = true
				break
			}
			if _, ok := e.names[name]; !ok && len(e.names) >= candidateLimit {
				e.overflow = ts
				e.dirty = true
				continue
			}
			if old, ok := e.names[name]; !ok || ts != old {
				e.dirty = true
			}
			e.names[name] = ts
			for _, alias := range aliases[name] {
				if normalized, err := NormalizeDomain(alias); err == nil {
					queue = append(queue, normalized)
				}
			}
		}
	}
	cutoff := ts - int64(candidateTTL.Seconds())
	for ip, e := range n.candidates {
		for name, seen := range e.names {
			if seen < cutoff {
				delete(e.names, name)
				e.dirty = true
			}
		}
		if e.overflow != 0 && e.overflow < cutoff {
			e.overflow = 0
			e.dirty = true
		}
		if len(e.names) == 0 && e.overflow == 0 && !e.dirty {
			delete(n.candidates, ip)
		}
	}
}

// Candidates returns fresh names and whether the set is incomplete. The latter
// must prevent classification; the legacy one-name cache does not prove it is complete.
func (n *Names) Candidates(ip netip.Addr, now time.Time) ([]string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	e := n.candidates[ip.Unmap()]
	if e == nil {
		return nil, true
	}
	cutoff := now.Add(-candidateTTL).Unix()
	names := make([]string, 0, len(e.names))
	for name, seen := range e.names {
		if seen >= cutoff {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, len(names) == 0 || (e.overflow >= cutoff && e.overflow != 0)
}

// CandidateRows snapshots dirty IPs. Empty-domain rows mark overflow; callers
// replace the complete IP set transactionally and acknowledge only on success.
func (n *Names) CandidateRows() map[string][]DNSCandidate {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := map[string][]DNSCandidate{}
	for ip, e := range n.candidates {
		if !e.dirty {
			continue
		}
		key := ip.String()
		rows := make([]DNSCandidate, 0, len(e.names)+1)
		for name, seen := range e.names {
			rows = append(rows, DNSCandidate{key, name, seen})
		}
		if e.overflow != 0 {
			rows = append(rows, DNSCandidate{key, "", e.overflow})
		}
		out[key] = rows
	}
	return out
}

// AckCandidateRows only clears a snapshot if the observations have not moved.
func (n *Names) AckCandidateRows(snapshot map[string][]DNSCandidate) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for raw, rows := range snapshot {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		e := n.candidates[ip]
		if e == nil {
			continue
		}
		count := len(e.names)
		if e.overflow != 0 {
			count++
		}
		if count != len(rows) {
			continue
		}
		same := true
		for _, r := range rows {
			if r.Domain == "" {
				same = same && e.overflow == r.Seen
			} else {
				seen, ok := e.names[r.Domain]
				same = same && ok && seen == r.Seen
			}
		}
		if same {
			e.dirty = false
			if count == 0 {
				delete(n.candidates, ip)
			}
		}
	}
}

func (n *Names) RestoreCandidate(row DNSCandidate, now time.Time) {
	ip, err := netip.ParseAddr(row.IP)
	if err != nil || row.Seen < now.Add(-candidateTTL).Unix() {
		return
	}
	ip = ip.Unmap()
	n.mu.Lock()
	defer n.mu.Unlock()
	e := n.candidates[ip]
	if e == nil {
		e = &candidateEntry{names: map[string]int64{}}
		n.candidates[ip] = e
	}
	if row.Domain == "" {
		if row.Seen > e.overflow {
			e.overflow = row.Seen
		}
		return
	}
	name, err := NormalizeDomain(row.Domain)
	if err != nil {
		return
	}
	if previous, exists := e.names[name]; exists {
		if row.Seen > previous {
			e.names[name] = row.Seen
		}
		return
	}
	if len(e.names) >= candidateLimit {
		if row.Seen > e.overflow {
			e.overflow = row.Seen
		}
		return
	}
	e.names[name] = row.Seen
}
