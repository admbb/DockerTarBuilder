package syncer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
)

type Recorder interface {
	Records(context.Context, time.Time, time.Time, string) (oxidns.Page, error)
}
type Syncer struct {
	mu        sync.Mutex
	Source    string
	Recorder  Recorder
	Store     *storage.Store
	PageDelay time.Duration
}

const ReplayLag = 5 * time.Minute

// RunInterval always uses a fixed upper bound. Pages are saved idempotently;
// only a fully traversed interval advances the durable checkpoint.
func (s *Syncer) RunInterval(ctx context.Context, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Store == nil || s.Recorder == nil || s.Source == "" {
		return fmt.Errorf("syncer is not configured")
	}
	start, from, err := s.Store.Coverage(ctx, s.Source)
	if err != nil {
		return err
	}
	upper := until.UnixMilli()
	if upper <= from {
		return fmt.Errorf("sync upper bound must advance")
	}
	status, err := s.Store.DNSStability(ctx, s.Source)
	if err != nil {
		return err
	}
	queryFrom := max(start, from-ReplayLag.Milliseconds())
	if status.ScannedUntilMS == from && from != 0 {
		// Backfill can advance by more than the replay lag. Re-read the
		// unsettled suffix and the trailing portion of previously stable data.
		queryFrom = max(start, status.UntilMS-ReplayLag.Milliseconds())
	}
	cursor := ""
	seen := map[string]bool{}
	for pageIndex := 0; pageIndex < 10000; pageIndex++ {
		page, err := s.Recorder.Records(ctx, time.UnixMilli(queryFrom), time.UnixMilli(upper), cursor)
		if err != nil {
			return err
		}
		if !page.OK {
			return fmt.Errorf("OxiDNS pagination failed")
		}
		for _, r := range page.Records {
			if r.CreatedAtMS < queryFrom || r.CreatedAtMS > upper {
				return fmt.Errorf("record outside requested time interval")
			}
		}
		if err = s.Store.SaveDNSScanPage(ctx, s.Source, page.Records, from); err != nil {
			return err
		}
		if page.NextCursor == "" {
			return s.Store.CompleteDNSScan(ctx, s.Source, from, queryFrom, upper, time.Now().UnixMilli(), ReplayLag.Milliseconds())
		}
		if seen[page.NextCursor] || page.NextCursor == cursor {
			return fmt.Errorf("repeated OxiDNS pagination cursor")
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
		if s.PageDelay > 0 {
			timer := time.NewTimer(s.PageDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("OxiDNS pagination exceeds safety limit")
}
