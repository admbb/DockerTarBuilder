package enrich

import (
	"fmt"
	"testing"
)

func TestNormalizeDomainIntelligence(t *testing.T) {
	cases := []struct {
		input, want string
		bad         bool
	}{
		{" Example.COM. ", "example.com", false}, {"例子.测试", "xn--fsqu00a.xn--0zwm56d", false},
		{"xn--fsqu00a.xn--0zwm56d", "xn--fsqu00a.xn--0zwm56d", false},
		{"", "", true}, {"192.0.2.1", "", true}, {"2001:db8::1", "", true},
		{"-bad.example", "", true}, {"a..example", "", true}, {"a_b.example", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeDomain(c.input)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("NormalizeDomain(%q) = %q, %v", c.input, got, err)
		}
	}
}

func TestDomainMatcherPrecedenceAndBoundaries(t *testing.T) {
	rules := []DomainRule{
		{Domain: "example.com", Match: "suffix", AppID: "a", Source: "community", Enabled: true},
		{Domain: "video.example.com", Match: "suffix", AppID: "b", Source: "curated", Enabled: true},
		{Domain: "exact.video.example.com", Match: "exact", AppID: "a", Source: "curated", Enabled: true},
		{Domain: "blocked.example.com", Match: "suffix", Exclude: true, Source: "curated", Enabled: true},
		{Domain: "special.blocked.example.com", Match: "exact", AppID: "b", Source: "curated", Enabled: true},
		{Domain: "override.example.com", Match: "suffix", AppID: "b", Source: "custom", User: true, Enabled: true},
		{Domain: "x.override.example.com", Match: "exact", AppID: "a", Source: "curated", Enabled: true},
		{Domain: "conflict.example.com", Match: "exact", AppID: "a", Source: "curated", Enabled: true},
		{Domain: "conflict.example.com", Match: "exact", AppID: "b", Source: "curated", Enabled: true},
	}
	m, err := BuildDomainMatcher(rules, map[string]bool{"a": true, "b": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		domain, app         string
		excluded, ambiguous bool
	}{
		{"EXAMPLE.COM.", "a", false, false}, {"www.example.com", "a", false, false}, {"notexample.com", "", false, false},
		{"example.com.evil.org", "", false, false}, {"video.example.com", "b", false, false},
		{"exact.video.example.com", "a", false, false}, {"blocked.example.com", "", true, false},
		{"special.blocked.example.com", "b", false, false}, {"x.override.example.com", "b", false, false},
		{"conflict.example.com", "", false, true},
	} {
		got := m.Match(c.domain)
		if got.AppID != c.app || got.Excluded != c.excluded || got.Ambiguous != c.ambiguous {
			t.Errorf("%s: %+v", c.domain, got)
		}
	}
	if got := m.MatchCandidates([]string{"example.com", "video.example.com"}); !got.Ambiguous || got.AppID != "" {
		t.Errorf("shared IP: %+v", got)
	}
	if got := m.MatchCandidates([]string{"example.com", "unknown.org"}); !got.Ambiguous || got.AppID != "" {
		t.Errorf("unresolved candidate: %+v", got)
	}
	if got := m.MatchCandidates([]string{"example.com", "www.example.com"}); got.AppID != "a" {
		t.Errorf("same application: %+v", got)
	}
}

func TestDomainMatcherRejectsUnsafeRules(t *testing.T) {
	for _, r := range []DomainRule{{Domain: "com", Match: "suffix", AppID: "a", Enabled: true}, {Domain: "co.uk", Match: "suffix", AppID: "a", Enabled: true}, {Domain: "example.com", Match: "suffix", AppID: "missing", Enabled: true}, {Domain: "example.com", Match: "regexp", AppID: "a", Enabled: true}} {
		if _, err := BuildDomainMatcher([]DomainRule{r}, map[string]bool{"a": true}); err == nil {
			t.Errorf("accepted unsafe rule: %+v", r)
		}
	}
}

func BenchmarkDomainMatcher(b *testing.B) {
	for _, size := range []int{10000, 50000, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			rules := make([]DomainRule, size)
			for i := range rules {
				rules[i] = DomainRule{Domain: fmt.Sprintf("d%d.example.com", i), Match: "suffix", AppID: "a", Enabled: true}
			}
			m, err := BuildDomainMatcher(rules, map[string]bool{"a": true})
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				m.Match("x.d123.example.com")
			}
		})
	}
}
