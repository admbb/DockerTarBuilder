package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"mikrotik-home-netflow-plus/internal/engine"
	"mikrotik-home-netflow-plus/internal/enrich"
	"mikrotik-home-netflow-plus/internal/flow"
	"mikrotik-home-netflow-plus/internal/store"
)

func TestDomainRuleAPIAuthorizationAndLifecycle(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(engine.Options{}, st, flow.NewTopology(nil, nil, nil), enrich.NewNames(100), nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	h := New(eng, st, nil, nil, nil, Info{App: "test"}, fstest.MapFS{"index.html": {Data: []byte("app")}}, "password", log).Handler()
	call := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth {
			req.SetBasicAuth("user", "password")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	body := `{"domain":"youtube.com","match":"suffix","appId":"youtube","enabled":true}`
	if got := call("POST", "/api/v1/domains/rules/test", `{"domain":"www.youtube.com"}`, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("test endpoint must require auth: %d", got.Code)
	}
	if got := call("POST", "/api/v1/domains/rules/test", `{"domain":"www.youtube.com"}`, true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"appId":"youtube"`) || !strings.Contains(got.Body.String(), `"sourceVersion"`) {
		t.Fatalf("builtin test: %d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/v1/domains/rules/test", `{"domain":"192.0.2.1"}`, true); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid test %d", got.Code)
	}
	if got := call("GET", "/api/v1/domains/builtin", "", true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"domain":"youtube.com"`) {
		t.Fatalf("builtin rules %d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/v1/domains/rules", body, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status %d", got.Code)
	}
	created := call("POST", "/api/v1/domains/rules", body, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"id":1`) {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	if got := call("POST", "/api/v1/domains/rules", body, true); got.Code != http.StatusConflict {
		t.Fatalf("conflict %d %s", got.Code, got.Body.String())
	}
	if got := call("GET", "/api/v1/domains/rules", "", true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "youtube.com") {
		t.Fatalf("list %d %s", got.Code, got.Body.String())
	}
	if got := call("DELETE", "/api/v1/domains/rules/1", "", true); got.Code != http.StatusOK {
		t.Fatalf("delete %d %s", got.Code, got.Body.String())
	}
	if got := call("DELETE", "/api/v1/domains/rules/1", "", true); got.Code != http.StatusNotFound {
		t.Fatalf("missing %d", got.Code)
	}
}
