package netflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlowSnapshotUsesBasicAuthAndUnchangedCounters(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "reader" || p != "secret" {
			t.Error("bad auth")
		}
		if r.URL.Path != "/api/v1/flows" || r.URL.Query().Get("limit") != "1000" || r.URL.Query().Get("offset") != "1000" {
			t.Errorf("bad query %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"foldBelow":10000,"rows":[{"id":42,"first":10,"last":20,"localIp":"192.168.1.2","remoteIp":"8.8.8.8","up":123,"down":456}]}`))
	}))
	defer s.Close()
	c, err := NewClient(s.URL, "reader", "secret")
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.FlowSnapshot(context.Background(), "1h", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if p.FoldBelow != 10000 || len(p.Rows) != 1 || p.Rows[0].Up != 123 {
		t.Fatalf("unexpected %+v", p)
	}
}
