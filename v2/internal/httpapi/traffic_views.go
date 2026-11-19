package httpapi

import (
	"context"
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

type trafficPoint struct {
	StartMS    int64        `json:"start_ms"`
	EndMS      int64        `json:"end_ms"`
	Observed   trafficCount `json:"observed"`
	Attributed trafficCount `json:"attributed"`
	Unknown    trafficCount `json:"unknown"`
	Selected   trafficCount `json:"selected"`
}

type trafficViewResponse struct {
	trafficRanking
	Device   string         `json:"device,omitempty"`
	Category string         `json:"category,omitempty"`
	App      *trafficItem   `json:"app,omitempty"`
	Points   []trafficPoint `json:"points,omitempty"`
	BucketMS int64          `json:"bucket_ms,omitempty"`
}

func (s *Server) appTrafficDetail(w http.ResponseWriter, r *http.Request) {
	s.trafficEndpoint(w, r, "app", r.PathValue("id"))
}

func (s *Server) trafficTrend(w http.ResponseWriter, r *http.Request) {
	s.trafficEndpoint(w, r, "trend", r.URL.Query().Get("app"))
}

func (s *Server) trafficCategories(w http.ResponseWriter, r *http.Request) {
	s.trafficEndpoint(w, r, "categories", "")
}

func (s *Server) trafficEndpoint(w http.ResponseWriter, r *http.Request, view, appID string) {
	apps, err := s.allApps(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "应用读取失败"})
		return
	}
	rules, err := s.effectiveRules(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "规则读取失败"})
		return
	}
	s.trafficView(w, r, apps, rules, view, appID)
}

func (s *Server) trafficView(w http.ResponseWriter, r *http.Request, apps []catalog.App, rules []correlation.Rule, view, appID string) {
	if !s.FlowEnabled {
		jsonResponse(w, http.StatusUnprocessableEntity, map[string]string{"error": "独立 IPFIX 采集器未启用"})
		return
	}
	device, ok := trafficClient(w, r)
	if !ok {
		return
	}
	_, from, to := rangeMillis(r)
	category := r.URL.Query().Get("category")
	out := trafficViewResponse{
		trafficRanking: trafficRanking{
			Metric: "bytes", FromMS: from, ToMS: to, Items: make([]trafficItem, 0),
			UnknownReasons: make(map[string]*trafficCount),
			Note:           "V2 独立 IPFIX 按接收时间统计外网字节。应用归属来自 DNS 证据推断，流量覆盖可能不完整。",
		},
		Device: device, Category: category,
	}
	byID := make(map[string]*trafficItem, len(apps))
	for _, app := range apps {
		byID[app.ID] = &trafficItem{ID: app.ID, Name: app.Name, Category: app.Category, Icon: app.Icon}
	}
	if appID != "" {
		out.App = byID[appID]
		if out.App == nil {
			jsonResponse(w, http.StatusNotFound, map[string]string{"error": "应用不存在"})
			return
		}
	}
	if view == "app" || view == "trend" {
		out.initPoints(from, to)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !s.scanTrafficView(ctx, &out, byID, rules) {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "IPFIX 应用流量暂不可用"})
		return
	}
	out.Inferred = out.Attributed
	switch view {
	case "ranking":
		for _, item := range byID {
			if item.Records > 0 && (category == "" || item.Category == category) {
				out.Items = append(out.Items, *item)
			}
		}
	case "categories":
		categories := make(map[string]*trafficItem)
		for _, item := range byID {
			if item.Records == 0 || (category != "" && item.Category != category) {
				continue
			}
			if categories[item.Category] == nil {
				categories[item.Category] = &trafficItem{ID: item.Category, Name: item.Category, Category: item.Category}
			}
			// Every application is already included in the checked attributed total.
			categories[item.Category].add(item.Up, item.Down, item.Records)
		}
		for _, item := range categories {
			out.Items = append(out.Items, *item)
		}
	}
	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.ID < b.ID
	})
	limit := 10
	if view == "categories" {
		limit = len(out.Items)
	}
	if requested, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && requested > 0 && requested <= 100 {
		limit = requested
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
	}
	jsonResponse(w, http.StatusOK, out)
}

func (out *trafficViewResponse) initPoints(from, to int64) {
	bucket := 5 * time.Minute
	switch elapsed := time.Duration(to-from) * time.Millisecond; {
	case elapsed > 7*24*time.Hour:
		bucket = 24 * time.Hour
	case elapsed > 24*time.Hour:
		bucket = 6 * time.Hour
	case elapsed > time.Hour:
		bucket = time.Hour
	}
	out.BucketMS = bucket.Milliseconds()
	for start := from; start < to; start += out.BucketMS {
		out.Points = append(out.Points, trafficPoint{StartMS: start, EndMS: min(start+out.BucketMS, to)})
	}
}

type trafficMatchKey struct {
	client, remote string
	start, end     int64
}

func (s *Server) scanTrafficView(ctx context.Context, out *trafficViewResponse, byID map[string]*trafficItem, rules []correlation.Rule) bool {
	stability, err := s.Store.DNSStability(ctx, s.Source)
	if err != nil {
		return false
	}
	out.AttributionEnabled = stability.UntilMS > stability.FromMS
	out.DNSEvidenceScope = "recorder_observed"
	out.DNSStableFromMS = stability.FromMS
	out.DNSStableUntilMS = stability.UntilMS
	if !out.AttributionEnabled && out.Device == "" && len(out.Points) == 0 {
		count, err := s.Store.ReceivedFlowTotals(ctx, out.FromMS, out.ToMS)
		if err != nil || !out.Observed.add(count.Up, count.Down, count.Records) {
			return false
		}
		out.Unknown = out.Observed
		if count.Records > 0 {
			out.UnknownReasons["dns_rescan_pending"] = &out.Unknown
		}
		return true
	}
	window := s.DNSCorrelationWindow
	if window == 0 {
		window = dnsTrafficWindow
	}
	analyzer := analysis.Analyzer{Store: s.Store, Source: s.Source, Window: window, Uncertainty: flow.ExporterTimeUncertainty, Rules: rules}
	var cursor *storage.TrafficSegment
	for {
		page, err := s.Store.TrafficSegments(ctx, out.FromMS, out.ToMS, out.Device, cursor)
		if err != nil {
			return false
		}
		matches := make(map[trafficMatchKey]correlation.Result)
		for _, segment := range page {
			match := correlation.Result{Reason: "dns_rescan_pending"}
			if out.AttributionEnabled {
				switch {
				case segment.TimeQuality != flow.ExporterEstimatedTime || segment.StartMS <= 0 || segment.EndMS < segment.StartMS || segment.EndMS > segment.ReceivedMS:
					match.Reason = "flow_time_unreliable"
				case segment.Proto != 6 && segment.Proto != 17:
					match.Reason = "unsupported_flow_protocol"
				case stability.FromMS <= max(int64(0), segment.StartMS-window.Milliseconds()) && segment.EndMS < stability.UntilMS:
					key := trafficMatchKey{segment.ClientIP, segment.RemoteIP, segment.StartMS, segment.EndMS}
					var cached bool
					if match, cached = matches[key]; !cached {
						match, err = analyzer.AnalyzeInterval(ctx, correlation.Flow{
							ClientIP: segment.ClientIP, RemoteIP: segment.RemoteIP, Start: time.UnixMilli(segment.StartMS),
						}, time.UnixMilli(segment.EndMS))
						if err != nil {
							return false
						}
						matches[key] = match
					}
				}
			}
			item := byID[match.AppID]
			if !out.countSegment(segment, item, match.Reason) {
				return false
			}
			if len(out.Points) > 0 {
				point := &out.Points[(segment.ReceivedMS-out.FromMS)/out.BucketMS]
				var up, down uint64
				if segment.Direction == flow.Up {
					up = segment.Bytes
				} else {
					down = segment.Bytes
				}
				point.Observed.add(up, down, 1)
				if item == nil {
					point.Unknown.add(up, down, 1)
					continue
				}
				point.Attributed.add(up, down, 1)
				if (out.App == nil || item.ID == out.App.ID) && (out.Category == "" || item.Category == out.Category) {
					point.Selected.add(up, down, 1)
				}
			}
		}
		if len(page) < storage.TrafficPageSize {
			if out.Attributed.Records == 0 {
				return true
			}
			after, err := s.Store.DNSStability(ctx, s.Source)
			if err != nil || after.FromMS > stability.FromMS || after.UntilMS < stability.UntilMS || after.EvidenceRevision != stability.EvidenceRevision {
				return false
			}
			out.DNSStableUntilMS = after.UntilMS
			return true
		}
		cursor = &page[len(page)-1]
	}
}
