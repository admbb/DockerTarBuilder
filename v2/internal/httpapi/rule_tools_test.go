package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"strings"
	"testing"
)

func testRuleTools(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server := &Server{Store: store, Password: "secret", Apps: []catalog.App{{ID: "builtin", Icon: "/icons/github.svg"}}}
	return server, server.Handler()
}

func ruleToolRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.SetBasicAuth("user", "secret")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func TestRuleBackupMergeAndRollback(t *testing.T) {
	s, h := testRuleTools(t)
	if _, err := s.Store.SaveUserRule(t.Context(), storage.UserRule{Domain: "existing.test", AppID: "builtin", Match: "exact"}); err != nil {
		t.Fatal(err)
	}
	bad := `{"version":1,"apps":[{"id":"local","name":"本地","category":"其他","icon":"/icons/github.svg"}],"rules":[{"domain":"test.example","app_id":"local","match":"suffix"},{"domain":"bad.example","app_id":"missing","match":"suffix"}]}`
	if got := ruleToolRequest(h, "POST", "/api/rules/import", bad); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid import: %d %s", got.Code, got.Body)
	}
	apps, err := s.Store.CustomApps(t.Context())
	if err != nil || len(apps) != 0 {
		t.Fatalf("rollback apps: %v %v", apps, err)
	}
	rules, err := s.Store.UserRules(t.Context())
	if err != nil || len(rules) != 1 || rules[0].Domain != "existing.test" {
		t.Fatalf("rollback rules: %v %v", rules, err)
	}
	body := strings.Replace(bad, `,{"domain":"bad.example","app_id":"missing","match":"suffix"}`, "", 1)
	for i := 0; i < 2; i++ {
		got := ruleToolRequest(h, "POST", "/api/rules/import", body)
		var result storage.RuleImportResult
		if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &result) != nil || result.AppsAdded != 1-i || result.RulesAdded != 1-i || result.RulesSkipped != i {
			t.Fatalf("import %d: %d %s", i, got.Code, got.Body)
		}
	}
	backup := ruleToolRequest(h, "GET", "/api/rules/export", "")
	var saved storage.RuleBackup
	if backup.Code != http.StatusOK || json.Unmarshal(backup.Body.Bytes(), &saved) != nil || len(saved.Apps) != 1 || len(saved.Rules) != 2 || saved.Apps[0].Icon != "/icons/github.svg" {
		t.Fatalf("export: %d %s", backup.Code, backup.Body)
	}
	_, fresh := testRuleTools(t)
	if got := ruleToolRequest(fresh, "POST", "/api/rules/import", backup.Body.String()); got.Code != http.StatusOK {
		t.Fatalf("reimport: %d %s", got.Code, got.Body)
	}
}

func TestUploadedAppIconAndReset(t *testing.T) {
	s, h := testRuleTools(t)
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0L24 24" stroke="#000"/></svg>`
	body, _ := json.Marshal(map[string]string{"svg": svg})
	if got := ruleToolRequest(h, "PUT", "/api/apps/builtin/icon", string(body)); got.Code != http.StatusOK {
		t.Fatalf("save SVG: %d %s", got.Code, got.Body)
	}
	apps, err := s.allApps(t.Context())
	if err != nil || len(apps) != 1 || !strings.HasPrefix(apps[0].Icon, "/api/apps/builtin/icon?v=") {
		t.Fatalf("uploaded icon path: %v %v", apps, err)
	}
	got := ruleToolRequest(h, "GET", apps[0].Icon, "")
	if got.Code != http.StatusOK || got.Body.String() != svg || got.Header().Get("Content-Security-Policy") == "" || got.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("serve SVG: %d %s %v", got.Code, got.Body, got.Header())
	}
	if got := ruleToolRequest(h, "PUT", "/api/apps/builtin/icon", `{"path":"//remote.test/asset.svg"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("external path: %d", got.Code)
	}
	if got := ruleToolRequest(h, "PUT", "/api/apps/builtin/icon", `{"reset":true}`); got.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", got.Code, got.Body)
	}
	apps, err = s.allApps(t.Context())
	if err != nil || len(apps) != 1 || apps[0].Icon != "/icons/github.svg" {
		t.Fatalf("restored icon: %v %v", apps, err)
	}
}

func TestSVGUploadRejectsActiveContent(t *testing.T) {
	prefix := `<svg xmlns="http://www.w3.org/2000/svg">`
	for _, svg := range []string{
		prefix + `<script/></svg>`,
		prefix + `<path onload="run()"/></svg>`,
		prefix + `<image href="https://remote.test/icon"/></svg>`,
		prefix + `<path fill="&#x75;Rl(https://remote.test/icon)"/></svg>`,
		prefix + `<path d="" style="fill:red"/></svg>`,
		prefix + `<foreignObject/></svg>`,
		prefix + `<path xmlns="http://www.w3.org/1999/xhtml"/></svg>`,
		`<!DOCTYPE svg SYSTEM "https://remote.test/dtd">` + prefix + `</svg>`,
		`<?xml-stylesheet href="https://remote.test/icons.css"?>` + prefix + `</svg>`,
		prefix + `</svg>` + prefix + `</svg>`,
		prefix + strings.Repeat(" ", maxSVGBytes) + `</svg>`,
	} {
		if validateSVG(svg) == nil {
			t.Errorf("accepted unsafe SVG: %.100s", svg)
		}
	}
}
