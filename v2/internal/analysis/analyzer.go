// Package analysis joins saved DNS evidence with NetFlow connection metadata.
// This layer never converts cumulative connection counters into time buckets.
package analysis

import (
	"context"
	"errors"
	"fmt"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/oxidns"
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
	// Retention can move the lower bound forward while evidence is queried.
	after, err := a.Store.DNSStability(ctx, a.Source)
	if err != nil {
		return correlation.Result{}, err
	}
	if after.FromMS > status.FromMS || after.UntilMS <= until || after.EvidenceRevision != status.EvidenceRevision {
		return correlation.Result{Reason: "dns_stability_changed"}, nil
	}
	return a.matchRecords(flow, end, records)
}

type Interval struct {
	Flow correlation.Flow
	End  time.Time
}

// AnalyzeBatch evaluates one page against the request watermark. The caller
// must discard attributed results if retention or the evidence revision changes.
func (a *Analyzer) AnalyzeBatch(ctx context.Context, intervals []Interval, status storage.DNSStability) ([]correlation.Result, error) {
	if len(intervals) == 0 {
		return nil, nil
	}
	if a.Store == nil || a.Source == "" {
		return nil, fmt.Errorf("analyzer not configured")
	}
	if a.Window != 30*time.Second && a.Window != 60*time.Second && a.Window != 120*time.Second {
		return nil, fmt.Errorf("invalid correlation window")
	}
	out := make([]correlation.Result, len(intervals))
	positions := make([]int, 0, len(intervals))
	queries := make([]storage.DNSCorrelationQuery, 0, len(intervals))
	for i, interval := range intervals {
		f := interval.Flow
		if f.Start.IsZero() || interval.End.Before(f.Start) || a.Uncertainty < 0 {
			return nil, fmt.Errorf("flow start is required")
		}
		earliest := f.Start.Add(-a.Uncertainty)
		until := interval.End.Add(a.Uncertainty).UnixMilli()
		from := max(int64(0), earliest.Add(-a.Window).UnixMilli())
		if status.UntilMS <= until || status.FromMS > from {
			out[i] = correlation.Result{Reason: "dns_rescan_pending"}
			continue
		}
		positions = append(positions, i)
		queries = append(queries, storage.DNSCorrelationQuery{
			Client: f.ClientIP, Remote: f.RemoteIP, RecentFrom: from, FlowStart: earliest.UnixMilli(), Until: until,
		})
	}
	records, err := a.Store.DNSCorrelationBatch(ctx, a.Source, queries)
	if err != nil {
		return nil, err
	}
	for j, position := range positions {
		if records[j] == nil {
			out[position] = correlation.Result{Reason: "dns_evidence_limit"}
			continue
		}
		interval := intervals[position]
		out[position], err = a.matchRecords(interval.Flow, interval.End, records[j])
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *Analyzer) matchRecords(f correlation.Flow, end time.Time, records []oxidns.Record) (correlation.Result, error) {
	events := make([]correlation.DNSEvent, 0, len(records))
	for _, record := range records {
		event, err := record.Evidence()
		if err != nil {
			return correlation.Result{}, err
		}
		events = append(events, event)
	}
	return correlation.MatchUncertainInterval(f, end, events, a.Rules, a.Window, a.Uncertainty), nil
}
