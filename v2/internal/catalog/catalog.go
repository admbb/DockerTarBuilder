// Package catalog loads the previously verified, locally bundled rules.
package catalog

import (
	"embed"
	"encoding/json"
	"netflow-plus-v2/internal/correlation"
)

//go:embed core.json applications.json V2FLY-LICENSE.txt
var files embed.FS

type App struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Icon     string `json:"icon"`
}
type sourceRule struct {
	Domain  string `json:"domain"`
	Match   string `json:"match"`
	AppID   string `json:"appId"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
}

func Load() ([]App, []correlation.Rule, error) {
	var apps struct {
		Applications []App `json:"applications"`
	}
	var data struct {
		Rules []sourceRule `json:"rules"`
	}
	a, err := files.ReadFile("applications.json")
	if err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(a, &apps); err != nil {
		return nil, nil, err
	}
	r, err := files.ReadFile("core.json")
	if err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(r, &data); err != nil {
		return nil, nil, err
	}
	var rules []correlation.Rule
	for _, v := range data.Rules {
		if v.Enabled && v.Source == "verified-curated" {
			rules = append(rules, correlation.Rule{Domain: v.Domain, AppID: v.AppID, Exact: v.Match == "exact"})
		}
	}
	return apps.Applications, rules, nil
}
