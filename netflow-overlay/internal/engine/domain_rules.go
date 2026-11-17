package engine

import (
	"errors"
	"fmt"
	"strings"

	"mikrotik-home-netflow-plus/internal/enrich"
	"mikrotik-home-netflow-plus/internal/store"
)

var ErrDomainUnavailable = errors.New("domain intelligence unavailable")
var ErrInvalidDomainRule = errors.New("invalid domain rule")
var ErrDomainRuleConflict = errors.New("conflicting domain rule")

func userDomainMatchRule(r store.UserDomainRule) enrich.DomainRule {
	return enrich.DomainRule{Domain: r.Domain, Match: r.Match, AppID: r.AppID, Exclude: r.Exclude, Enabled: r.Enabled, User: true, Source: "user", Confidence: "user"}
}

func (e *Engine) DomainApplications() ([]enrich.DomainApplication, error) {
	c, err := enrich.LoadStarterDomainCatalog()
	if err != nil {
		return nil, err
	}
	return c.Applications, nil
}
func (e *Engine) DomainRules() ([]store.UserDomainRule, error) {
	if !e.domainCandidatesActive {
		return nil, ErrDomainUnavailable
	}
	return e.st.LoadUserDomainRules()
}

// TestDomain matches one supplied name only; it does not establish which
// application owns a real connection sharing the same IP address.
func (e *Engine) TestDomain(domain string) (enrich.DomainMatch, string, error) {
	name, err := enrich.NormalizeDomain(domain)
	if err != nil {
		return enrich.DomainMatch{}, "", ErrInvalidDomainRule
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.domainCandidatesActive || e.domainMatcher == nil {
		return enrich.DomainMatch{}, "", ErrDomainUnavailable
	}
	match := e.domainMatcher.Match(name)
	return match, e.domainApps[match.AppID], nil
}

func (e *Engine) BuiltinDomainRules() ([]enrich.DomainRule, error) {
	catalog, err := enrich.LoadStarterDomainCatalog()
	if err != nil {
		return nil, err
	}
	result := make([]enrich.DomainRule, 0)
	for _, rule := range catalog.Rules {
		if rule.Enabled && rule.Source == "verified-curated" {
			result = append(result, rule)
		}
	}
	return result, nil
}

// buildUserMatcher validates every rule, including disabled ones. Callers
// publish only after the database mutation succeeds.
func (e *Engine) buildUserMatcher(rules []store.UserDomainRule) (*enrich.DomainMatcher, error) {
	ids := make(map[string]bool, len(e.domainApps))
	for id := range e.domainApps {
		ids[id] = true
	}
	catalog, err := enrich.LoadStarterDomainCatalog()
	if err != nil {
		return nil, err
	}
	var all []enrich.DomainRule
	for _, r := range catalog.Rules {
		if r.Source == "verified-curated" {
			all = append(all, r)
		}
	}
	active := make(map[string]bool, len(rules))
	identities := make(map[string]bool, len(rules))
	for _, r := range rules {
		check := userDomainMatchRule(r)
		check.Enabled = true
		if _, err := enrich.BuildDomainMatcher([]enrich.DomainRule{check}, ids); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidDomainRule, err)
		}
		key := r.Domain + "\x00" + r.Match
		identity := key + "\x00" + r.AppID + fmt.Sprint(r.Exclude)
		if identities[identity] || (r.Enabled && active[key]) {
			return nil, ErrDomainRuleConflict
		}
		identities[identity] = true
		if r.Enabled {
			active[key] = true
		}
		all = append(all, userDomainMatchRule(r))
	}
	return enrich.BuildDomainMatcher(all, ids)
}

func (e *Engine) SaveDomainRule(rule store.UserDomainRule) (store.UserDomainRule, error) {
	e.domainConfigMu.Lock()
	defer e.domainConfigMu.Unlock()
	if !e.domainCandidatesActive || e.domainApps == nil {
		return rule, ErrDomainUnavailable
	}
	normalized, err := enrich.NormalizeDomain(rule.Domain)
	if err != nil {
		return rule, fmt.Errorf("%w: domain", ErrInvalidDomainRule)
	}
	rule.Domain = normalized
	rule.Match = strings.TrimSpace(rule.Match)
	rule.AppID = strings.TrimSpace(rule.AppID)
	if rule.Exclude {
		rule.AppID = ""
	}
	rules, err := e.st.LoadUserDomainRules()
	if err != nil {
		return rule, err
	}
	found := false
	for i := range rules {
		if rule.ID != 0 && rules[i].ID == rule.ID {
			rules[i] = rule
			found = true
			break
		}
	}
	if rule.ID != 0 && !found {
		return rule, store.ErrDomainRuleNotFound
	}
	if rule.ID == 0 {
		rules = append(rules, rule)
	}
	matcher, err := e.buildUserMatcher(rules)
	if err != nil {
		return rule, err
	}
	id, err := e.st.SaveUserDomainRule(rule)
	if err != nil {
		return rule, err
	}
	rule.ID = id
	e.mu.Lock()
	e.domainMatcher = matcher
	e.mu.Unlock()
	return rule, nil
}

func (e *Engine) DeleteDomainRule(id int64) error {
	e.domainConfigMu.Lock()
	defer e.domainConfigMu.Unlock()
	if !e.domainCandidatesActive || e.domainApps == nil {
		return ErrDomainUnavailable
	}
	rules, err := e.st.LoadUserDomainRules()
	if err != nil {
		return err
	}
	remaining := make([]store.UserDomainRule, 0, len(rules))
	found := false
	for _, r := range rules {
		if r.ID == id {
			found = true
		} else {
			remaining = append(remaining, r)
		}
	}
	if !found {
		return store.ErrDomainRuleNotFound
	}
	matcher, err := e.buildUserMatcher(remaining)
	if err != nil {
		return err
	}
	if err = e.st.DeleteUserDomainRule(id); err != nil {
		return err
	}
	e.mu.Lock()
	e.domainMatcher = matcher
	e.mu.Unlock()
	return nil
}
