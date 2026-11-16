// Package enrich: application attribution for DNS names. This engine never
// infers an application from an IP, a keyword, or a shared CDN alone.
package enrich

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type DomainRule struct {
	Domain     string `json:"domain"`
	Match      string `json:"match"` // exact or suffix
	AppID      string `json:"appId"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Exclude    bool   `json:"exclude"`
	User       bool   `json:"user"`
	Enabled    bool   `json:"enabled"`
}

type DomainMatch struct {
	AppID      string `json:"appId,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Source     string `json:"source,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	MatchedBy  string `json:"matchedBy,omitempty"`
	Ambiguous  bool   `json:"ambiguous"`
	Excluded   bool   `json:"excluded"`
}

type domainNode struct {
	children      map[string]*domainNode
	exact, suffix []DomainRule
}
type DomainMatcher struct{ root *domainNode }
type AtomicDomainMatcher struct{ current atomic.Pointer[DomainMatcher] }

// NormalizeDomain rejects IP literals, invalid labels and public suffix rules.
func NormalizeDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" {
		return "", fmt.Errorf("empty domain")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("IP address is not a domain")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA domain: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("invalid domain length or labels")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid DNS character")
			}
		}
	}
	return ascii, nil
}

// BuildDomainMatcher validates before publishing; conflicts remain unresolved.
func BuildDomainMatcher(rules []DomainRule, appIDs map[string]bool) (*DomainMatcher, error) {
	root := &domainNode{children: map[string]*domainNode{}}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		d, err := NormalizeDomain(rule.Domain)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Domain, err)
		}
		if suffix, _ := publicsuffix.PublicSuffix(d); suffix == d {
			return nil, fmt.Errorf("rule %q: public suffix", d)
		}
		if rule.Match != "exact" && rule.Match != "suffix" {
			return nil, fmt.Errorf("rule %q: invalid match", d)
		}
		if !rule.Exclude && !appIDs[rule.AppID] {
			return nil, fmt.Errorf("rule %q: unknown application", d)
		}
		if rule.Confidence == "low" && !rule.User {
			continue
		}
		rule.Domain = d
		node := root
		labels := strings.Split(d, ".")
		for i := len(labels) - 1; i >= 0; i-- {
			if node.children[labels[i]] == nil {
				node.children[labels[i]] = &domainNode{children: map[string]*domainNode{}}
			}
			node = node.children[labels[i]]
		}
		if rule.Match == "exact" {
			node.exact = append(node.exact, rule)
		} else {
			node.suffix = append(node.suffix, rule)
		}
	}
	return &DomainMatcher{root: root}, nil
}

// Match chooses a user rule first, then the most specific domain, then exact.
// Equal-precedence rules with different outcomes are ambiguous, independent of order.
func (m *DomainMatcher) Match(host string) DomainMatch {
	h, err := NormalizeDomain(host)
	if err != nil || m == nil || m.root == nil {
		return DomainMatch{}
	}
	labels := strings.Split(h, ".")
	node := m.root
	type candidate struct {
		rule  DomainRule
		depth int
		exact bool
	}
	var candidates []candidate
	for i := len(labels) - 1; i >= 0; i-- {
		node = node.children[labels[i]]
		if node == nil {
			break
		}
		depth := len(labels) - i
		for _, r := range node.suffix {
			candidates = append(candidates, candidate{r, depth, false})
		}
		if i == 0 {
			for _, r := range node.exact {
				candidates = append(candidates, candidate{r, depth, true})
			}
		}
	}
	if len(candidates) == 0 {
		return DomainMatch{}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.rule.User != b.rule.User {
			return a.rule.User
		}
		if a.depth != b.depth {
			return a.depth > b.depth
		}
		if a.exact != b.exact {
			return a.exact
		}
		return false
	})
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.rule.User != best.rule.User || c.depth != best.depth || c.exact != best.exact {
			break
		}
		if c.rule.AppID != best.rule.AppID || c.rule.Exclude != best.rule.Exclude {
			return DomainMatch{Domain: h, Ambiguous: true}
		}
	}
	if best.rule.Exclude {
		return DomainMatch{Domain: h, Excluded: true, Source: best.rule.Source}
	}
	return DomainMatch{AppID: best.rule.AppID, Domain: h, Source: best.rule.Source, Confidence: best.rule.Confidence, MatchedBy: best.rule.Match}
}

// MatchCandidates only attributes an IP if every observed name is known and
// agrees; otherwise the connection cannot be reliably associated with an app.
func (m *DomainMatcher) MatchCandidates(names []string) DomainMatch {
	if len(names) == 0 {
		return DomainMatch{}
	}
	var result DomainMatch
	for _, name := range names {
		next := m.Match(name)
		if next.Ambiguous || next.Excluded || next.AppID == "" {
			return DomainMatch{Ambiguous: len(names) > 1 || next.Ambiguous}
		}
		if result.AppID != "" && result.AppID != next.AppID {
			return DomainMatch{Ambiguous: true}
		}
		if result.AppID == "" {
			result = next
		}
	}
	return result
}
func (a *AtomicDomainMatcher) Load() *DomainMatcher   { return a.current.Load() }
func (a *AtomicDomainMatcher) Store(m *DomainMatcher) { a.current.Store(m) }
