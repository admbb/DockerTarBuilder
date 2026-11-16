package engine

import (
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

func TestDomainApplicationClassificationAndFallback(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	names := enrich.NewNames(100)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(Options{}, st, flow.NewTopology(nil, nil, nil), names, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	eng.domainMatcher, err = enrich.BuildDomainMatcher([]enrich.DomainRule{{Domain: "youtube.com", Match: "suffix", AppID: "youtube", Source: "test", Enabled: true}}, map[string]bool{"youtube": true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.20")
	names.Observe([]enrich.DNSRecord{{Type: "A", Name: "www.youtube.com", Data: ip.String()}}, now)
	dest, name := eng.destOf(ip, flow.ZoneWAN, "")
	if dest.Kind != "app" || dest.Key != "app:youtube" || name != "www.youtube.com" {
		t.Fatalf("application: %+v name %q", dest, name)
	}
	names.Observe([]enrich.DNSRecord{{Type: "A", Name: "other.example.org", Data: ip.String()}}, now)
	dest, _ = eng.destOf(ip, flow.ZoneWAN, "")
	if dest.Kind != "domain" {
		t.Fatalf("shared address must fall back: %+v", dest)
	}
	local, _ := eng.destOf(ip, flow.ZoneSite, "office")
	if local.Kind != "site" {
		t.Fatalf("site handling changed: %+v", local)
	}
	eng.Flush(now)
}

func TestLegacyDNSNameDoesNotEstablishCompleteCandidates(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ip := "192.0.2.21"
	now := time.Now()
	if err = st.Write(&store.Batch{DNS: []store.DNSName{{IP: ip, Name: "www.youtube.com", Seen: now.Unix()}}}); err != nil {
		t.Fatal(err)
	}
	names := enrich.NewNames(100)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := New(Options{}, st, flow.NewTopology(nil, nil, nil), names, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	names.Observe([]enrich.DNSRecord{{Type: "A", Name: "www.youtube.com", Data: ip}}, now)
	dest, _ := eng.destOf(netip.MustParseAddr(ip), flow.ZoneWAN, "")
	if dest.Kind != "domain" {
		t.Fatalf("legacy cache is incomplete: %+v", dest)
	}
}
