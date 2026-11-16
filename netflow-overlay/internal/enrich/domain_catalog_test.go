package enrich

import "testing"

func TestStarterDomainCatalogLoads(t *testing.T) {
	c, err := LoadStarterDomainCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Applications) == 0 || len(c.Rules) == 0 {
		t.Fatal("starter catalog is empty")
	}
	ids := map[string]bool{}
	for _, a := range c.Applications {
		ids[a.ID] = true
	}
	m, err := BuildDomainMatcher(c.Rules, ids)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match("api.openai.com"); got.AppID != "openai_api" {
		t.Fatalf("unexpected match: %+v", got)
	}
	if got := m.Match("cdn.cloudflare.net"); got.AppID != "" {
		t.Fatalf("shared CDN attributed: %+v", got)
	}
}
