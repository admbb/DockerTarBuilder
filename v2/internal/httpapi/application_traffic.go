package httpapi

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"netflow-plus-v2/internal/analysis"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/flow"
	"netflow-plus-v2/internal/storage"
)

const dnsTrafficWindow = 60 * time.Second

type trafficCount struct {
	storage.FlowTotals
	Bytes uint64 `json:"bytes"`
}

func (c *trafficCount) add(up, down, records uint64) bool {
	if up > math.MaxUint64-down || c.Bytes > math.MaxUint64-up-down || c.Records > math.MaxUint64-records {
		return false
	}
	c.Up += up
	c.Down += down
	c.Records += records
	c.Bytes += up + down
	return true
}

type trafficItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Icon     string `json:"icon"`
	trafficCount
}

type trafficRanking struct {
	Metric             string                   `json:"metric"`
	Items              []trafficItem            `json:"items"`
	Observed           trafficCount             `json:"observed"`
	Attributed         trafficCount             `json:"attributed"`
	Unknown            trafficCount             `json:"unknown"`
	UnknownReasons     map[string]*trafficCount `json:"unknown_reasons"`
	CoverageComplete   bool                     `json:"coverage_complete"`
	AttributionEnabled bool                     `json:"attribution_enabled"`
	FromMS             int64                    `json:"from_ms"`
	ToMS               int64                    `json:"to_ms"`
	Note               string                   `json:"note"`
}

func (s *Server) trafficEvidenceVerified(now time.Time) bool {
	return !s.DNSVerifiedFrom.IsZero() && s.DNSVerifiedUntil.After(s.DNSVerifiedFrom) && !s.DNSVerifiedUntil.After(now)
}

func (s *Server) trafficSummary(r *http.Request) map[string]any {
	enabled := s.FlowEnabled && s.trafficEvidenceVerified(time.Now())
	out := map[string]any{
		"app_traffic_available":           s.FlowEnabled,
		"app_traffic_attribution_enabled": enabled,
		"app_traffic_coverage_complete":   false,
	}
	switch {
	case !s.FlowEnabled:
		out["app_traffic_reason"] = "ipfix_not_configured"
	case !enabled:
		out["app_traffic_reason"] = "dns_completeness_unverified"
	default:
		out["app_traffic_reason"] = "observed_ipfix_only"
	}
	return out
}

func (s *Server) trafficTop(w http.ResponseWriter, r *http.Request, apps []catalog.App, rules []correlation.Rule) {
	if !s.FlowEnabled {
		jsonResponse(w, http.StatusUnprocessableEntity, map[string]string{"error": "IPFIX collector is not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	_, from, to := rangeMillis(r)
	ranking := trafficRanking{
		Metric: "bytes", FromMS: from, ToMS: to,
		Items: make([]trafficItem, 0), UnknownReasons: make(map[string]*trafficCount),
		AttributionEnabled: s.trafficEvidenceVerified(time.UnixMilli(to)),
		Note:               "Observed WAN IPFIX delta bytes in the collector receive-time interval. DNS-matched segments are inferred application traffic; coverage may be incomplete.",
	}
	if !s.fillTrafficRanking(ctx, &ranking, apps, rules) {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "IPFIX application traffic unavailable"})
		return
	}
	sort.Slice(ranking.Items, func(i, j int) bool {
		a, b := ranking.Items[i], ranking.Items[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.ID < b.ID
	})
	limit := 10
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 100 {
		limit = v
	}
	if len(ranking.Items) > limit {
		ranking.Items = ranking.Items[:limit]
	}
	jsonResponse(w, http.StatusOK, ranking)
}

func (s *Server) fillTrafficRanking(ctx context.Context, ranking *trafficRanking, apps []catalog.App, rules []correlation.Rule) bool {
	if !ranking.AttributionEnabled {
		count, err := s.Store.ReceivedFlowTotals(ctx, ranking.FromMS, ranking.ToMS)
		if err != nil || !ranking.Observed.add(count.Up, count.Down, count.Records) {
			return false
		}
		ranking.Unknown = ranking.Observed
		if count.Records > 0 {
			ranking.UnknownReasons["dns_completeness_unverified"] = &ranking.Unknown
		}
		return true
	}

	byID := make(map[string]*trafficItem, len(apps))
	for _, app := range apps {
		byID[app.ID] = &trafficItem{ID: app.ID, Name: app.Name, Category: app.Category, Icon: app.Icon}
	}
	analyzer := analysis.Analyzer{
		Store: s.Store, Source: s.Source, Window: dnsTrafficWindow,
		Rules: rules, EvidenceComplete: true,
	}
	var cursor *storage.TrafficSegment
	for {
		page, err := s.Store.TrafficSegments(ctx, ranking.FromMS, ranking.ToMS, cursor)
		if err != nil {
			return false
		}
		for _, segment := range page {
			match, err := s.matchTrafficSegment(ctx, &analyzer, segment)
			if err != nil || !ranking.countSegment(segment, byID[match.AppID], match.Reason) {
				return false
			}
		}
		if len(page) < storage.TrafficPageSize {
			break
		}
		cursor = &page[len(page)-1]
	}
	for _, item := range byID {
		if item.Bytes != 0 {
			ranking.Items = append(ranking.Items, *item)
		}
	}
	return true
}

func (s *Server) matchTrafficSegment(ctx context.Context, analyzer *analysis.Analyzer, segment storage.TrafficSegment) (correlation.Result, error) {
	if segment.TimeQuality != "estimated" || segment.StartMS <= 0 || segment.EndMS < segment.StartMS || segment.EndMS > segment.ReceivedMS {
		return correlation.Result{Reason: "flow_time_unreliable"}, nil
	}
	if segment.Proto != 6 && segment.Proto != 17 {
		return correlation.Result{Reason: "unsupported_flow_protocol"}, nil
	}
	start, end := time.UnixMilli(segment.StartMS), time.UnixMilli(segment.EndMS)
	if start.Add(-dnsTrafficWindow).Before(s.DNSVerifiedFrom) || end.After(s.DNSVerifiedUntil) {
		return correlation.Result{Reason: "outside_verified_dns_interval"}, nil
	}
	return analyzer.AnalyzeInterval(ctx, correlation.Flow{
		ClientIP: segment.ClientIP, RemoteIP: segment.RemoteIP, Start: start,
	}, end)
}

func (r *trafficRanking) countSegment(s storage.TrafficSegment, item *trafficItem, reason string) bool {
	var up, down uint64
	switch s.Direction {
	case flow.Up:
		up = s.Bytes
	case flow.Down:
		down = s.Bytes
	default:
		return false
	}
	if !r.Observed.add(up, down, 1) {
		return false
	}
	if item != nil {
		return item.add(up, down, 1) && r.Attributed.add(up, down, 1)
	}
	if reason == "dns_client_ip_ttl" {
		reason = "application_missing"
	}
	if r.UnknownReasons[reason] == nil {
		r.UnknownReasons[reason] = &trafficCount{}
	}
	return r.UnknownReasons[reason].add(up, down, 1) && r.Unknown.add(up, down, 1)
}
