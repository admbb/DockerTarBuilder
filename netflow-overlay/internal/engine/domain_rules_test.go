package engine

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"mikrotik-home-netflow-plus/internal/enrich"
	"mikrotik-home-netflow-plus/internal/flow"
	"mikrotik-home-netflow-plus/internal/store"
)

func TestUserDomainRulesPersistAndPublish(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	names := enrich.NewNames(100)
	mk := func(n *enrich.Names) *Engine {
		e, err := New(Options{}, st, flow.NewTopology(nil, nil, nil), n, nil, nil, log)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := mk(names)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.54")
	names.Observe([]enrich.DNSRecord{{Type: "A", Name: "www.youtube.com", Data: ip.String()}}, now)
	before, _ := e.destOf(ip, flow.ZoneWAN, "")
	if before.Key != "app:youtube" {
		t.Fatalf("verified starter rule unavailable: %+v", before)
	}
	saved, err := e.SaveDomainRule(store.UserDomainRule{Domain: "YOUTUBE.COM.", Match: "suffix", AppID: "youtube", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == 0 || saved.Domain != "youtube.com" {
		t.Fatalf("saved %+v", saved)
	}
	dest, _ := e.destOf(ip, flow.ZoneWAN, "")
	if dest.Key != "app:youtube" {
		t.Fatalf("not published: %+v", dest)
	}
	_, err = e.SaveDomainRule(store.UserDomainRule{Domain: "youtube.com", Match: "suffix", AppID: "netflix", Enabled: true})
	if !errors.Is(err, ErrDomainRuleConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	_, err = e.SaveDomainRule(store.UserDomainRule{Domain: "co.uk", Match: "suffix", AppID: "youtube", Enabled: true})
	if !errors.Is(err, ErrInvalidDomainRule) {
		t.Fatalf("unsafe public suffix: %v", err)
	}
	dest, _ = e.destOf(ip, flow.ZoneWAN, "")
	if dest.Key != "app:youtube" {
		t.Fatal("failed mutation replaced active index")
	}
	e.Flush(now)
	restartedNames := enrich.NewNames(100)
	restarted := mk(restartedNames)
	got, _ := restarted.destOf(ip, flow.ZoneWAN, "")
	if got.Key != "app:youtube" {
		t.Fatalf("restart lost rule or candidates: %+v", got)
	}
	saved.Enabled = false
	if _, err = e.SaveDomainRule(saved); err != nil {
		t.Fatal(err)
	}
	if got := e.domainMatcher.Match("www.youtube.com"); got.Source != "verified-curated" {
		t.Fatalf("disabled user rule must fall back to verified rule: %+v", got)
	}
	if err = e.DeleteDomainRule(saved.ID); err != nil {
		t.Fatal(err)
	}
	if err = e.DeleteDomainRule(saved.ID); !errors.Is(err, store.ErrDomainRuleNotFound) {
		t.Fatalf("expected missing: %v", err)
	}
}

func TestRuleChangeDoesNotRelabelExistingConnection(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "connection.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	names := enrich.NewNames(100)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := New(Options{}, st, flow.NewTopology(nil, nil, nil), names, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	remote := netip.MustParseAddr("192.0.2.77")
	names.Observe([]enrich.DNSRecord{{Type: "A", Name: "video.example.com", Data: remote.String()}}, now)
	f := flow.Flow{Start: now, End: now.Add(time.Second), LocalIP: netip.MustParseAddr("192.168.1.2"), RemoteIP: remote, LocalPort: 1000, RemotePort: 443, Proto: 6, Dir: flow.Up, Zone: flow.ZoneWAN, Router: true, Bytes: 100, Packets: 1}
	e.AddFlows(now, []flow.Flow{f})
	original := e.conns[f.Key()].dest
	if original.Kind != "domain" {
		t.Fatalf("unexpected initial destination: %+v", original)
	}
	if _, err = e.SaveDomainRule(store.UserDomainRule{Domain: "example.com", Match: "suffix", AppID: "youtube", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.Start = now.Add(2 * time.Second)
	f.End = f.Start.Add(time.Second)
	f.Bytes = 200
	e.AddFlows(f.End, []flow.Flow{f})
	if c := e.conns[f.Key()]; c.dest != original || c.up != 300 {
		t.Fatalf("old connection changed: %+v", c)
	}
	f.LocalPort++
	f.Start = now.Add(4 * time.Second)
	f.End = f.Start.Add(time.Second)
	f.Bytes = 400
	e.AddFlows(f.End, []flow.Flow{f})
	current := e.conns[f.Key()].dest
	if current.Key != "app:youtube" {
		t.Fatalf("new connection not matched: %+v", current)
	}
	e.Flush(now.Add(time.Minute))
	for _, hourly := range []bool{false, true} {
		rows, err := st.Top(store.Filter{From: 0, To: now.Add(time.Hour).Unix(), Hourly: hourly}, "dest", 10)
		if err != nil {
			t.Fatal(err)
		}
		totals := map[int64]store.TopRow{}
		for _, row := range rows {
			totals[row.ID] = row
		}
		if totals[original.ID].Up != 300 || totals[original.ID].Conns != 1 || totals[current.ID].Up != 400 || totals[current.ID].Conns != 1 {
			t.Fatalf("hourly=%v: %+v", hourly, totals)
		}
	}
}
