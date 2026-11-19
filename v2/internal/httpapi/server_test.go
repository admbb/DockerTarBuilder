package httpapi

import (
	"net/http"
	"net/http/httptest"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"testing"
)

func TestAuthenticationAndUnavailableByteRanking(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := (&Server{Store: st, Source: "test", Password: "secret"}).Handler()
	call := func(path string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if auth {
			r.SetBasicAuth("user", "secret")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := call("/api/ha/summary", false).Code; got != 401 {
		t.Fatalf("unauthorized %d", got)
	}
	if got := call("/api/apps/top?metric=bytes", true).Code; got != 422 {
		t.Fatalf("invented byte ranking: %d", got)
	}
	if got := call("/api/apps/top?metric=dns", true).Code; got != 200 {
		t.Fatalf("dns ranking %d", got)
	}
}
