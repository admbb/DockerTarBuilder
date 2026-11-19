package httpapi

import (
	"math"
	"time"

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
	Inferred           trafficCount             `json:"inferred"`
	Unknown            trafficCount             `json:"unknown"`
	UnknownReasons     map[string]*trafficCount `json:"unknown_reasons"`
	CoverageComplete   bool                     `json:"coverage_complete"`
	AttributionEnabled bool                     `json:"attribution_enabled"`
	DNSEvidenceScope   string                   `json:"dns_evidence_scope"`
	DNSStableFromMS    int64                    `json:"dns_stable_from_ms"`
	DNSStableUntilMS   int64                    `json:"dns_stable_until_ms"`
	FromMS             int64                    `json:"from_ms"`
	ToMS               int64                    `json:"to_ms"`
	Note               string                   `json:"note"`
}

func (s *Server) trafficSummary(status storage.DNSStability, answerIndexReady bool) map[string]any {
	enabled := s.FlowEnabled && status.UntilMS > status.FromMS && answerIndexReady
	out := map[string]any{
		"app_traffic_available":           s.FlowEnabled,
		"app_traffic_attribution_enabled": enabled,
		"app_traffic_coverage_complete":   false,
		"dns_evidence_scope":              "recorder_observed",
		"dns_stable_from_ms":              status.FromMS,
		"dns_stable_until_ms":             status.UntilMS,
		"dns_last_scan":                   status,
	}
	switch {
	case !s.FlowEnabled:
		out["app_traffic_reason"] = "ipfix_not_configured"
	case status.UntilMS <= status.FromMS:
		out["app_traffic_reason"] = "dns_rescan_pending"
	case !answerIndexReady:
		out["app_traffic_reason"] = "dns_index_building"
	default:
		out["app_traffic_reason"] = "dns_recorder_inferred"
	}
	return out
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
