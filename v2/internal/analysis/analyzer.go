// Package analysis joins saved DNS evidence with NetFlow connection metadata.
// This layer never converts cumulative connection counters into time buckets.
package analysis

import (
	"context"
	"fmt"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/storage"
	"time"
)

type Analyzer struct {
	Store  *storage.Store
	Source string
	Window time.Duration
	Rules  []correlation.Rule
	// EvidenceComplete must only be set after verifying upstream ingestion
	// completeness; a successful checkpoint alone does not prove it.
	EvidenceComplete bool
}

func (a *Analyzer) Analyze(ctx context.Context, flow correlation.Flow) (correlation.Result, error) {
	return a.AnalyzeInterval(ctx, flow, flow.Start)
}

func (a *Analyzer) AnalyzeInterval(ctx context.Context, flow correlation.Flow, end time.Time) (correlation.Result, error) {
	if a.Store == nil || a.Source == "" {
		return correlation.Result{}, fmt.Errorf("analyzer not configured")
	}
	if a.Window != 30*time.Second && a.Window != 60*time.Second && a.Window != 120*time.Second {
		return correlation.Result{}, fmt.Errorf("invalid correlation window")
	}
	if flow.Start.IsZero() || end.Before(flow.Start) {
		return correlation.Result{}, fmt.Errorf("flow start is required")
	}
	start, checkpoint, err := a.Store.Coverage(ctx, a.Source)
	if err != nil {
		return correlation.Result{}, err
	}
	if checkpoint < end.UnixMilli() || start > max(int64(0), flow.Start.Add(-a.Window).UnixMilli()) {
		return correlation.Result{Reason: "dns_sync_incomplete"}, nil
	}
	if !a.EvidenceComplete {
		return correlation.Result{Reason: "dns_completeness_unverified"}, nil
	}
	from := max(int64(0), flow.Start.Add(-a.Window).UnixMilli())
	records, err := a.Store.EventsForClient(ctx, a.Source, flow.ClientIP, from, end.UnixMilli(), 10000)
	if err != nil {
		return correlation.Result{}, err
	}
	events := make([]correlation.DNSEvent, 0, len(records))
	for _, record := range records {
		event, err := record.Evidence()
		if err != nil {
			return correlation.Result{}, err
		}
		events = append(events, event)
	}
	return correlation.MatchInterval(flow, end, events, a.Rules, a.Window), nil
}
