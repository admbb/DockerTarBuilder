package httpapi

import (
	"net/http/httptest"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesPersistAndRejectCrossOrigin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	st, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Password: "secret", Apps: []catalog.App{{ID: "x", Name: "Example"}}}
	h := s.Handler()
	call := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost/api/rules", strings.NewReader(`{"domain":"Example.COM.","app_id":"x","match":"suffix","priority":100}`))
		r.SetBasicAuth("user", "secret")
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := call("http://evil.example").Code; got != 403 {
		t.Fatalf("cross origin: %d", got)
	}
	if got := call("http://localhost").Code; got != 200 {
		t.Fatalf("save: %d", got)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s.Store = st
	rules, err := s.effectiveRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := correlation.MatchDomain(rules, "sub.example.com"); !ok || id != "x" {
		t.Fatalf("persisted rule: %v %q", ok, id)
	}
}
