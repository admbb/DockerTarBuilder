package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
)

func TestTrafficViewsFilterAndBalance(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	start := now.Add(-20 * time.Minute)
	seen := start.Add(time.Minute)
	client := netip.MustParseAddr("192.168.1.10")
	other := netip.MustParseAddr("192.168.1.11")
	remote := netip.MustParseAddr("8.8.8.8")
	if err := db.SavePage(ctx, "dns", []oxidns.Record{{
		ID: 1, CreatedAtMS: start.Add(-5 * time.Second).UnixMilli(),
		ClientIP: client.String(), HasResponse: true, RCode: "NOERROR",
		Questions: []oxidns.Question{{Name: "one.example", QType: "A"}},
		Answers:   []oxidns.Answer{{Name: "one.example", Type: "A", Data: remote.String(), TTL: 30}},
	}}); err != nil {
		t.Fatal(err)
	}
	firstScan := now.Add(-3 * time.Minute).UnixMilli()
	if err := db.CompleteDNSScan(ctx, "dns", 0, 0, firstScan, now.UnixMilli(), time.Minute.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDNSScan(ctx, "dns", firstScan, 0, now.UnixMilli(), now.UnixMilli(), time.Minute.Milliseconds()); err != nil {
		t.Fatal(err)
	}
	base := flow.Flow{Zone: flow.ZoneWAN, Start: start, End: start.Add(time.Second),
		LocalIP: client, RemoteIP: remote, Proto: 6, Dir: flow.Up, Bytes: 120, TimeQuality: flow.ExporterEstimatedTime}
	second := base
	second.LocalIP, second.Dir, second.Bytes = other, flow.Down, 80
	exporter := netip.MustParseAddr("192.168.1.1")
	if accepted, err := db.SaveFlowMessage(ctx, exporter, sha256.Sum256([]byte("before end")), seen,
		[]flow.Flow{base, second}, 1, 1, 2); err != nil || !accepted {
		t.Fatalf("save = %v, %v", accepted, err)
	}
	if accepted, err := db.SaveFlowMessage(ctx, exporter, sha256.Sum256([]byte("at end")), seen.Add(time.Minute),
		[]flow.Flow{base}, 1, 3, 1); err != nil || !accepted {
		t.Fatalf("save at end = %v, %v", accepted, err)
	}
	s := Server{Store: db, FlowEnabled: true, Source: "dns", Password: "test",
		Apps:  []catalog.App{{ID: "one", Name: "One", Category: "video"}},
		Rules: []correlation.Rule{{Domain: "one.example", AppID: "one"}},
	}
	handler := s.Handler()
	query := "?range=custom&from_ms=" + strconv.FormatInt(seen.UnixMilli(), 10) +
		"&to_ms=" + strconv.FormatInt(seen.Add(time.Minute).UnixMilli(), 10)
	request := func(path string, status int, out any) {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.SetBasicAuth("user", "test")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s: HTTP %d, %s", path, w.Code, w.Body)
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	var ranking trafficViewResponse
	request("/api/apps/top"+query+"&metric=bytes&device="+client.String()+"&category=video", http.StatusOK, &ranking)
	if ranking.Observed.Bytes != 120 || ranking.Unknown.Bytes != 0 || ranking.Inferred.Bytes != 120 ||
		len(ranking.Items) != 1 || ranking.Device != client.String() || ranking.FromMS != seen.UnixMilli() {
		t.Fatalf("ranking: %+v", ranking)
	}
	var categories trafficViewResponse
	request("/api/ha/top_categories"+query, http.StatusOK, &categories)
	if categories.Observed.Bytes != 200 || categories.Unknown.Down != 80 ||
		len(categories.Items) != 1 || categories.Items[0].ID != "video" || categories.Items[0].Up != 120 {
		t.Fatalf("categories: %+v", categories)
	}
	var detail trafficViewResponse
	request("/api/apps/one"+query, http.StatusOK, &detail)
	if detail.App == nil || detail.App.Bytes != 120 || len(detail.Points) != 1 ||
		detail.Points[0].Selected.Bytes != 120 || detail.Points[0].Observed.Bytes != 200 ||
		detail.Points[0].EndMS != seen.Add(time.Minute).UnixMilli() {
		t.Fatalf("detail: %+v", detail)
	}
	var trend trafficViewResponse
	request("/api/apps/trend"+query+"&device="+other.String(), http.StatusOK, &trend)
	if len(trend.Points) != 1 || trend.Points[0].Unknown.Bytes != 80 || trend.Points[0].Attributed.Bytes != 0 {
		t.Fatalf("trend: %+v", trend)
	}
	var devices struct{ Items []storage.TrafficDevice }
	request("/api/traffic/devices"+query, http.StatusOK, &devices)
	if len(devices.Items) != 2 || devices.Items[0].IP != client.String() || devices.Items[0].Up != 120 {
		t.Fatalf("devices: %+v", devices)
	}
	request("/api/apps/missing"+query, http.StatusNotFound, nil)
	request("/api/apps/trend"+query+"&device=invalid", http.StatusBadRequest, nil)
	request("/api/apps/top?range=custom&from_ms=1", http.StatusBadRequest, nil)
}
