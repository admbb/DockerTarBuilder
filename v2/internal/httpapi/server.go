// Package httpapi provides read-only V2 analytics and Home Assistant endpoints.
package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/netflow"
	"netflow-plus-v2/internal/storage"
	"sort"
	"strconv"
	"time"
)

type Server struct {
	Store                *storage.Store
	Source               string
	Netflow              *netflow.Client
	Password             string
	Apps                 []catalog.App
	Rules                []correlation.Rule
	FlowEnabled          bool
	DNSCorrelationWindow time.Duration
}

// Protect challenges on initial navigation as well as API requests so a
// browser can establish HTTP Basic credentials before loading the dashboard.
func Protect(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, supplied, ok := r.BasicAuth()
		if password == "" || !ok || subtle.ConstantTimeCompare([]byte(supplied), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="NetFlow V2", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type appStat struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Icon     string `json:"icon"`
	Queries  int64  `json:"queries"`
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, p, ok := r.BasicAuth()
		if s.Password == "" || !ok || subtle.ConstantTimeCompare([]byte(p), []byte(s.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="NetFlow V2", charset="UTF-8"`)
			jsonResponse(w, 401, map[string]string{"error": "authentication required"})
			return
		}
		h(w, r)
	}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /api/summary", s.analytics(s.summary))
	m.HandleFunc("GET /api/ha/summary", s.analytics(s.summary))
	m.HandleFunc("GET /api/apps", s.auth(s.apps))
	m.HandleFunc("POST /api/apps", s.auth(s.createApp))
	m.HandleFunc("GET /api/apps/top", s.analytics(s.top))
	m.HandleFunc("GET /api/ha/top_apps", s.analytics(s.top))
	m.HandleFunc("GET /api/unknown", s.analytics(s.unknown))
	m.HandleFunc("GET /api/rules", s.auth(s.listRules))
	m.HandleFunc("POST /api/rules", s.auth(s.writeRule))
	m.HandleFunc("PUT /api/rules/{id}", s.auth(s.writeRule))
	m.HandleFunc("DELETE /api/rules/{id}", s.auth(s.deleteRule))
	m.HandleFunc("GET /api/devices", s.auth(s.devices))
	m.HandleFunc("GET /api/devices/top", s.auth(s.devices))
	m.HandleFunc("GET /api/ha/top_devices", s.auth(s.devices))
	m.HandleFunc("GET /api/apps/{id}", s.analytics(s.appTrafficDetail))
	m.HandleFunc("GET /api/apps/{id}/traffic", s.analytics(s.appTrafficDetail))
	m.HandleFunc("GET /api/apps/trend", s.analytics(s.trafficTrend))
	m.HandleFunc("GET /api/traffic/trend", s.analytics(s.trafficTrend))
	m.HandleFunc("GET /api/categories", s.analytics(s.trafficCategories))
	m.HandleFunc("GET /api/ha/categories", s.analytics(s.trafficCategories))
	m.HandleFunc("GET /api/ha/top_categories", s.analytics(s.trafficCategories))
	m.HandleFunc("GET /api/traffic/devices", s.analytics(s.trafficDevices))
	s.registerRuleTools(m)
	return m
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	if s.Netflow == nil {
		jsonResponse(w, 503, map[string]string{"error": "NetFlow Plus is not configured"})
		return
	}
	value, _, _ := rangeMillis(r)
	devices, err := s.Netflow.Devices(r.Context(), value)
	if err != nil {
		jsonResponse(w, 502, map[string]string{"error": "NetFlow Plus unavailable"})
		return
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Up+devices[i].Down > devices[j].Up+devices[j].Down })
	limit := 10
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	if len(devices) > limit {
		devices = devices[:limit]
	}
	jsonResponse(w, 200, map[string]any{"range": value, "items": devices, "source": "netflow_plus", "note": "existing external traffic aggregates"})
}
func rangeMillis(r *http.Request) (string, int64, int64) {
	q := r.URL.Query()
	if q.Get("range") == "custom" || q.Has("from_ms") || q.Has("to_ms") {
		from, _ := strconv.ParseInt(q.Get("from_ms"), 10, 64)
		to, _ := strconv.ParseInt(q.Get("to_ms"), 10, 64)
		return "custom", from, to
	}
	value := q.Get("range")
	var d time.Duration
	switch value {
	case "1h":
		d = time.Hour
	case "24h":
		d = 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		value = "7d"
		d = 7 * 24 * time.Hour
	}
	now := time.Now().UnixMilli()
	return value, now - d.Milliseconds(), now
}
func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	value, from, to := rangeMillis(r)
	start, end, err := s.Store.Coverage(r.Context(), s.Source)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "storage unavailable"})
		return
	}
	result := map[string]any{"range": value, "dns_coverage_start_ms": start, "dns_synced_until_ms": end, "requested_from_ms": from, "requested_to_ms": to, "app_traffic_available": false, "app_traffic_reason": "per-application byte attribution is not yet complete or verified"}
	status, err := s.Store.DNSStability(r.Context(), s.Source)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "storage unavailable"})
		return
	}
	answerIndexReady := false
	if s.FlowEnabled && status.UntilMS > status.FromMS {
		answerIndexReady, err = s.Store.DNSAnswerIndexReady(r.Context())
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "storage unavailable"})
			return
		}
	}
	for key, value := range s.trafficSummary(status, answerIndexReady) {
		result[key] = value
	}
	if s.FlowEnabled {
		observed, err := s.Store.ReceivedFlowTotals(r.Context(), from, to)
		if err != nil {
			result["v2_flow_error"] = "V2 flow totals unavailable"
		} else {
			result["v2_flow"] = observed
			result["v2_flow_note"] = "Observed WAN IPFIX bytes by receive time; coverage may be incomplete"
		}
		if health, err := s.Store.FlowHealth(r.Context()); err == nil {
			result["v2_flow_health"] = health
		}
	}
	if s.Netflow != nil && value != "custom" {
		ov, err := s.Netflow.Overview(r.Context(), value)
		if err == nil {
			result["traffic"] = ov
		} else {
			result["traffic_error"] = "NetFlow Plus unavailable"
		}
	}
	jsonResponse(w, 200, result)
}
func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.allApps(r.Context())
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "应用读取失败"})
		return
	}
	jsonResponse(w, 200, apps)
}
func (s *Server) domainCounts(r *http.Request) ([]storage.DomainCount, int64, int64, error) {
	_, from, to := rangeMillis(r)
	rows, err := s.Store.DNSPopularity(r.Context(), s.Source, from, to, 1000)
	return rows, from, to, err
}
func (s *Server) top(w http.ResponseWriter, r *http.Request) {
	rules, ruleErr := s.effectiveRules(r.Context())
	if ruleErr != nil {
		jsonResponse(w, 500, map[string]string{"error": "规则读取失败"})
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric == "bytes" {
		apps, err := s.allApps(r.Context())
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "应用读取失败"})
			return
		}
		s.trafficView(w, r, apps, rules, "ranking", "")
		return
	}
	if metric != "" && metric != "dns" {
		jsonResponse(w, 422, map[string]string{"error": "application byte ranking is unavailable until a reliable flow data source is connected"})
		return
	}
	rows, from, to, err := s.domainCounts(r)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "DNS statistics unavailable"})
		return
	}
	byID := map[string]*appStat{}
	apps, err := s.allApps(r.Context())
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "应用读取失败"})
		return
	}
	for _, app := range apps {
		a := app
		byID[a.ID] = &appStat{ID: a.ID, Name: a.Name, Category: a.Category, Icon: a.Icon}
	}
	var unknown int64
	for _, row := range rows {
		app, ok := correlation.MatchDomain(rules, row.Domain)
		if !ok || byID[app] == nil {
			unknown += row.Queries
			continue
		}
		byID[app].Queries += row.Queries
	}
	out := make([]appStat, 0)
	for _, app := range byID {
		if app.Queries > 0 {
			out = append(out, *app)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Queries != out[j].Queries {
			return out[i].Queries > out[j].Queries
		}
		return out[i].ID < out[j].ID
	})
	limit := 10
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 100 {
		limit = v
	}
	if len(out) > limit {
		out = out[:limit]
	}
	jsonResponse(w, 200, map[string]any{"metric": "dns_queries", "items": out, "unknown_queries": unknown, "truncated_domains": len(rows) == 1000, "from_ms": from, "to_ms": to, "note": "DNS queries are not traffic bytes"})
}
func (s *Server) unknown(w http.ResponseWriter, r *http.Request) {
	rules, ruleErr := s.effectiveRules(r.Context())
	if ruleErr != nil {
		jsonResponse(w, 500, map[string]string{"error": "规则读取失败"})
		return
	}
	rows, from, to, err := s.domainCounts(r)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "DNS statistics unavailable"})
		return
	}
	out := make([]storage.DomainCount, 0)
	for _, row := range rows {
		if _, ok := correlation.MatchDomain(rules, row.Domain); !ok {
			out = append(out, row)
		}
	}
	jsonResponse(w, 200, map[string]any{"items": out, "from_ms": from, "to_ms": to, "truncated_domains": len(rows) == 1000})
}
