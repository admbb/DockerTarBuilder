package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/collector"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/httpapi"
	"netflow-plus-v2/internal/ipfix"
	"netflow-plus-v2/internal/netflow"
	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
	"netflow-plus-v2/internal/syncer"
	"netflow-plus-v2/web"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func env(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}
func main() {
	password := os.Getenv("APP_PASSWORD")
	if password == "" {
		log.Fatal("APP_PASSWORD is required")
	}
	path := env("DB_PATH", "/data/app.db")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	apps, rules, err := catalog.Load()
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	src := env("OXIDNS_SOURCE_ID", "oxidns-query-recorder")
	base := os.Getenv("OXIDNS_BASE_URL")
	if base != "" {
		recorder, err := oxidns.NewClient(base, env("OXIDNS_RECORDER_TAG", "query_recorder_main"), os.Getenv("OXIDNS_USERNAME"), os.Getenv("OXIDNS_PASSWORD"))
		if err != nil {
			log.Fatal(err)
		}
		if err = db.InitializeSource(ctx, src, time.Now().Add(-30*24*time.Hour).UnixMilli()); err != nil {
			log.Fatal(err)
		}
		poller := &syncer.Syncer{Source: src, Recorder: recorder, Store: db, PageDelay: 100 * time.Millisecond}
		interval := 60
		retentionDays := 30
		if v, e := strconv.Atoi(env("DNS_RETENTION_DAYS", "30")); e == nil && v >= 1 && v <= 365 {
			retentionDays = v
		}
		if v, e := strconv.Atoi(env("POLL_INTERVAL_SECONDS", "60")); e == nil && v >= 15 && v <= 3600 {
			interval = v
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, current, e := db.Coverage(ctx, src)
				if e != nil {
					log.Printf("DNS progress unavailable: %v", e)
				} else {
					until := time.Now().Add(-2 * time.Minute)
					if end := time.UnixMilli(current).Add(24 * time.Hour); until.After(end) {
						until = end
					}
					if until.UnixMilli() > current {
						if e = poller.RunInterval(ctx, until); e != nil {
							log.Printf("DNS synchronization failed: %v", e)
						} else if e = db.PruneDNSBefore(ctx, src, time.Now().Add(-time.Duration(retentionDays)*24*time.Hour).UnixMilli()); e != nil {
							log.Printf("DNS retention failed: %v", e)
						}
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(interval) * time.Second):
				}
			}
		}()
	}
	var netflowClient *netflow.Client
	if base := os.Getenv("NETFLOW_PLUS_BASE_URL"); base != "" {
		netflowClient, err = netflow.NewClient(base, env("NETFLOW_PLUS_USERNAME", "v2"), os.Getenv("NETFLOW_PLUS_PASSWORD"))
		if err != nil {
			log.Fatal(err)
		}
	}
	if listen := os.Getenv("FLOW_LISTEN"); listen != "" {
		local := []netip.Prefix{}
		for _, part := range strings.Split(os.Getenv("LOCAL_NETWORKS"), ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
			if err != nil {
				log.Fatal("invalid LOCAL_NETWORKS")
			}
			local = append(local, prefix)
		}
		if len(local) == 0 {
			log.Fatal("LOCAL_NETWORKS is required when FLOW_LISTEN is set")
		}
		allowed := map[netip.Addr]bool{}
		for _, part := range strings.Split(os.Getenv("FLOW_EXPORTERS"), ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil {
				log.Fatal("invalid FLOW_EXPORTERS")
			}
			allowed[addr.Unmap()] = true
		}
		if len(allowed) == 0 {
			log.Fatal("FLOW_EXPORTERS is required when FLOW_LISTEN is set")
		}
		_, portString, err := net.SplitHostPort(listen)
		if err != nil {
			log.Fatal("FLOW_LISTEN must be a UDP listen address")
		}
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || port == 0 {
			log.Fatal("invalid FLOW_LISTEN port")
		}
		topo := flow.NewTopology(local, nil, nil)
		ignored := map[netip.AddrPort]bool{}
		for _, part := range strings.Split(os.Getenv("FLOW_IGNORE_EXPORT_TARGETS"), ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			target, err := netip.ParseAddrPort(strings.TrimSpace(part))
			if err != nil {
				log.Fatal("invalid FLOW_IGNORE_EXPORT_TARGETS")
			}
			ignored[netip.AddrPortFrom(target.Addr().Unmap(), target.Port())] = true
		}
		// Templates from a previous process cannot be tied to a confirmed
		// exporter boot. Wait for fresh templates rather than reuse stale ones.
		instance := &collector.Collector{Store: db, Decoder: ipfix.NewDecoder(""), Normalizer: flow.NewNormalizer(topo, time.Minute, uint16(port)), Allowed: allowed, IgnoreExportTargets: ignored}
		flowRetentionDays := 30
		if v, e := strconv.Atoi(env("FLOW_RETENTION_DAYS", "30")); e == nil && v >= 1 && v <= 365 {
			flowRetentionDays = v
		}
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-ticker.C:
					if err := db.PruneFlowBefore(ctx, now.Add(-time.Duration(flowRetentionDays)*24*time.Hour).UnixMilli()); err != nil {
						log.Printf("V2 flow retention failed: %v", err)
					}
				}
			}
		}()
		go func() {
			if err := instance.Run(ctx, listen); err != nil {
				log.Printf("V2 IPFIX collector stopped: %v", err)
				stop()
			}
		}()
	}
	service := (&httpapi.Server{Store: db, Source: src, Netflow: netflowClient, Password: password, Apps: apps, Rules: rules, FlowEnabled: os.Getenv("FLOW_LISTEN") != ""}).Handler()
	assets, err := fs.Sub(web.Files, "dist")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", service)
	mux.Handle("/healthz", service)
	mux.Handle("/", httpapi.Protect(password, http.FileServer(http.FS(assets))))
	port := env("APP_PORT", "8088")
	if p, e := strconv.Atoi(port); e != nil || p < 1 || p > 65535 {
		log.Fatal("APP_PORT must be a TCP port")
	}
	server := &http.Server{Addr: fmt.Sprintf(":%s", port), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("NetFlow V2 listening on port %s", port)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
