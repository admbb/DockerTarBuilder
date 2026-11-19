// Package analysis joins saved DNS evidence with NetFlow connection metadata.
// This layer never converts cumulative connection counters into time buckets.
package analysis

import (
	"context"
	"errors"
	"fmt"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/storage"
	"time"
)

type Analyzer struct {
	Store       *storage.Store
	Source      string
	Window      time.Duration
	Uncertainty time.Duration
	Rules       []correlation.Rule
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
	if flow.Start.IsZero() || end.Before(flow.Start) || a.Uncertainty < 0 {
		return correlation.Result{}, fmt.Errorf("flow start is required")
	}
	status, err := a.Store.DNSStability(ctx, a.Source)
	if err != nil {
		return correlation.Result{}, err
	}
	earliest := flow.Start.Add(-a.Uncertainty)
	until := end.Add(a.Uncertainty).UnixMilli()
	from := max(int64(0), earliest.Add(-a.Window).UnixMilli())
	if status.UntilMS <= until || status.FromMS > from {
		return correlation.Result{Reason: "dns_rescan_pending"}, nil
	}
	records, err := a.Store.DNSCorrelationEvents(ctx, a.Source, flow.ClientIP, flow.RemoteIP, from, earliest.UnixMilli(), until, 10000)
	if err != nil {
		if errors.Is(err, storage.ErrDNSEvidenceLimit) {
			return correlation.Result{Reason: "dns_evidence_limit"}, nil
		}
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
	// Retention can move the lower bound forward while evidence is queried.
	after, err := a.Store.DNSStability(ctx, a.Source)
	if err != nil {
		return correlation.Result{}, err
	}
	if after.FromMS > status.FromMS || after.UntilMS <= until || after.EvidenceRevision != status.EvidenceRevision {
		return correlation.Result{Reason: "dns_stability_changed"}, nil
	}
	return correlation.MatchUncertainInterval(flow, end, events, a.Rules, a.Window, a.Uncertainty), nil
}
