package enrich

import (
	"embed"
	"encoding/json"
	"fmt"
)

// The starter library is shipped inside the existing Go binary. It is data,
// separate from the matcher, and never changes a user's mutable rules.
//
//go:embed domain-library/catalog/*.json domain-library/curated/*.json domain-library/V2FLY-LICENSE.txt
var starterDomainLibrary embed.FS

type DomainApplication struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type DomainCatalog struct {
	Applications []DomainApplication
	Rules        []DomainRule
}

func LoadStarterDomainCatalog() (DomainCatalog, error) {
	var result DomainCatalog
	raw, err := starterDomainLibrary.ReadFile("domain-library/catalog/applications.json")
	if err != nil {
		return result, err
	}
	var apps struct {
		Version      int                 `json:"version"`
		Applications []DomainApplication `json:"applications"`
	}
	if err = json.Unmarshal(raw, &apps); err != nil {
		return result, err
	}
	if apps.Version != 1 {
		return result, fmt.Errorf("unsupported catalog version")
	}
	ids := map[string]bool{}
	for _, app := range apps.Applications {
		if app.ID == "" || app.Name == "" || app.Category == "" || ids[app.ID] {
			return result, fmt.Errorf("invalid or duplicate application %q", app.ID)
		}
		ids[app.ID] = true
	}
	raw, err = starterDomainLibrary.ReadFile("domain-library/curated/core.json")
	if err != nil {
		return result, err
	}
	var rules struct {
		Version int          `json:"version"`
		Rules   []DomainRule `json:"rules"`
	}
	if err = json.Unmarshal(raw, &rules); err != nil {
		return result, err
	}
	if rules.Version != 1 {
		return result, fmt.Errorf("unsupported rules version")
	}
	if _, err = BuildDomainMatcher(rules.Rules, ids); err != nil {
		return result, err
	}
	result.Applications, result.Rules = apps.Applications, rules.Rules
	return result, nil
}
