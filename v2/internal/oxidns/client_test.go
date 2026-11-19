package oxidns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecordsBasicAuthAndCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "reader" || pass != "secret" {
			t.Error("missing basic authentication")
		}
		if r.URL.Path != "/api/plugins/query_recorder_main/records" || r.URL.Query().Get("cursor") != "1000:7" || r.URL.Query().Get("limit") != "500" {
			t.Errorf("unexpected request: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"next_cursor":"999:6","records":[{"id":7,"created_at_ms":1000,"client_ip":"192.0.2.3","has_response":true,"rcode":"No Error","questions_json":[{"name":"example.com.","qtype":"A"}],"answers_json":[{"name":"example.com.","rr_type":"A","ttl":30,"payload_text":"8.8.8.8"}]}]}`))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "query_recorder_main", "reader", "secret")
	if err != nil {
		t.Fatal(err)
	}
	page, err := c.Records(context.Background(), time.Unix(0, 0), time.Unix(2, 0), "1000:7")
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor != "999:6" || len(page.Records) != 1 || page.Records[0].Answers[0].TTL != 30 {
		t.Fatalf("unexpected page: %+v", page)
	}
}
func TestRecordsRejectsUnauthorizedWithoutLeakingBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("sensitive response"))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "recorder", "reader", "secret")
	_, err := c.Records(context.Background(), time.Now(), time.Now(), "")
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error: %v", err)
	}
}
