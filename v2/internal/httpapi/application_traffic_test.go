package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
)

func TestTrafficRankingBalancesObservedBytes(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	start := now.Add(-2 * time.Minute)
	client := netip.MustParseAddr("192.168.1.10")
	remote := netip.MustParseAddr("8.8.8.8")
	ev := oxidns.Record{
		ID: 1, CreatedAtMS: start.Add(-5 * time.Second).UnixMilli(),
		ClientIP: client.String(), HasResponse: true, RCode: "NOERROR",
		Questions: []oxidns.Question{{Name: "one.example", QType: "A"}},
		Answers:   []oxidns.Answer{{Name: "one.example", Type: "A", Data: remote.String(), TTL: 10}},
	}
	if err := db.SavePage(ctx, "dns", []oxidns.Record{ev}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteInterval(ctx, "dns", 0, now.Add(-time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}

	base := flow.Flow{Zone: flow.ZoneWAN, Start: start, End: start.Add(time.Second),
		LocalIP: client, RemoteIP: remote, Proto: 6, Dir: flow.Up, Bytes: 120, TimeQuality: "estimated"}
	afterTTL := base
	afterTTL.Dir, afterTTL.Bytes, afterTTL.End = flow.Down, 80, start.Add(6*time.Second)
	local := base
	local.Zone, local.Bytes = flow.ZoneLocal, 1000
	receiveOnly := base
	receiveOnly.TimeQuality, receiveOnly.Bytes = "receive_only", 10
	rows := []flow.Flow{base, afterTTL, local, receiveOnly}
	exporter := netip.MustParseAddr("192.168.1.1")
	accepted, err := db.SaveFlowMessage(ctx, exporter, sha256.Sum256([]byte("example")), now.Add(-time.Minute), rows, 1, 1, uint32(len(rows)))
	if err != nil || !accepted {
		t.Fatalf("save = %v, %v", accepted, err)
	}

	s := Server{Store: db, FlowEnabled: true, Source: "dns"}
	apps := []catalog.App{{ID: "one", Name: "One"}}
	rules := []correlation.Rule{{Domain: "one.example", AppID: "one"}}
	request := func() trafficRanking {
		t.Helper()
		response := httptest.NewRecorder()
		s.trafficTop(response, httptest.NewRequest("GET", "/api/apps/top?metric=bytes&range=1h", nil), apps, rules)
		var rank trafficRanking
		if err := json.Unmarshal(response.Body.Bytes(), &rank); response.Code != http.StatusOK || err != nil {
			t.Fatalf("HTTP %d, body %s, error %v", response.Code, response.Body, err)
		}
		return rank
	}
	unverified := request()
	if unverified.AttributionEnabled || unverified.CoverageComplete || len(unverified.Items) != 0 ||
		unverified.Observed.Bytes != 210 || unverified.Unknown.Bytes != 210 ||
		unverified.UnknownReasons["dns_completeness_unverified"].Records != 3 {
		t.Fatalf("unverified: %+v", unverified)
	}
	s.DNSVerifiedFrom, s.DNSVerifiedUntil = start.Add(-2*time.Minute), now.Add(-time.Minute)
	verified := request()
	if !verified.AttributionEnabled || len(verified.Items) != 1 || verified.Items[0].Bytes != 120 ||
		verified.Observed.Up != 130 || verified.Observed.Down != 80 || verified.Observed.Records != 3 ||
		verified.Attributed.Bytes != 120 || verified.Unknown.Bytes != 90 ||
		verified.UnknownReasons["dns_segment_not_covered"].Bytes != 80 ||
		verified.UnknownReasons["flow_time_unreliable"].Bytes != 10 {
		t.Fatalf("verified: %+v", verified)
	}
}
