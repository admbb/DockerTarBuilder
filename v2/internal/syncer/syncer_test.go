package syncer

import (
	"context"
	"errors"
	"netflow-plus-v2/internal/oxidns"
	"netflow-plus-v2/internal/storage"
	"path/filepath"
	"testing"
	"time"
)

type fakeRecorder struct {
	fail  bool
	loop  bool
	calls int
	late  bool
	older bool
}

func (f *fakeRecorder) Records(ctx context.Context, since, until time.Time, cursor string) (oxidns.Page, error) {
	f.calls++
	if cursor == "" {
		events := []oxidns.Record{{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.2"}}
		if f.late {
			events = append(events, oxidns.Record{ID: 3, CreatedAtMS: 1500, ClientIP: "192.168.1.2"})
		}
		if f.older {
			events = append(events, oxidns.Record{ID: 4, CreatedAtMS: 1700, ClientIP: "192.168.1.2"})
		}
		var records []oxidns.Record
		for _, ev := range events {
			if ev.CreatedAtMS >= since.UnixMilli() && ev.CreatedAtMS <= until.UnixMilli() {
				records = append(records, ev)
			}
		}
		return oxidns.Page{OK: true, NextCursor: "cursor-1", Records: records}, nil
	}
	if f.fail {
		return oxidns.Page{}, errors.New("temporary failure")
	}
	if f.loop {
		return oxidns.Page{OK: true, NextCursor: "cursor-1"}, nil
	}
	page := oxidns.Page{OK: true}
	if since.UnixMilli() <= 2000 && until.UnixMilli() >= 2000 {
		page.Records = []oxidns.Record{{ID: 2, CreatedAtMS: 2000, ClientIP: "192.168.1.3"}}
	}
	return page, nil
}
func TestPartialFailureDoesNotAdvanceAndRetryIsIdempotent(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	rec := &fakeRecorder{fail: true}
	s := Syncer{Source: "test", Recorder: rec, Store: db}
	if err = s.RunInterval(ctx, time.UnixMilli(3000)); err == nil {
		t.Fatal("expected page failure")
	}
	checkpoint, err := db.Checkpoint(ctx, "test")
	if err != nil || checkpoint != 0 {
		t.Fatalf("checkpoint %d %v", checkpoint, err)
	}
	rec.fail = false
	if err = s.RunInterval(ctx, time.UnixMilli(3000)); err != nil {
		t.Fatal(err)
	}
	checkpoint, err = db.Checkpoint(ctx, "test")
	if err != nil || checkpoint != 3000 {
		t.Fatalf("checkpoint %d %v", checkpoint, err)
	}
}
func TestPaginationLoopDoesNotAdvance(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := Syncer{Source: "test", Recorder: &fakeRecorder{loop: true}, Store: db}
	ctx := context.Background()
	if err = s.RunInterval(ctx, time.UnixMilli(3000)); err == nil {
		t.Fatal("expected cursor loop error")
	}
	checkpoint, err := db.Checkpoint(ctx, "test")
	if err != nil || checkpoint != 0 {
		t.Fatalf("checkpoint %d %v", checkpoint, err)
	}
}

func TestRescanWatermarkWaitsForLateEventAndSurvivesRetry(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	recorder := &fakeRecorder{}
	s := Syncer{Source: "test", Recorder: recorder, Store: db}
	check := func(wantScan, wantStable int64) {
		t.Helper()
		got, err := db.DNSStability(ctx, s.Source)
		if err != nil || got.ScannedUntilMS != wantScan || got.UntilMS != wantStable {
			t.Fatalf("status %+v; error %v; expected scan %d and stable %d", got, err, wantScan, wantStable)
		}
	}
	if err := s.RunInterval(ctx, time.UnixMilli(3000)); err != nil {
		t.Fatal(err)
	}
	check(3000, 0)
	recorder.late, recorder.fail = true, true
	upper := ReplayLag.Milliseconds() + 4000
	if err := s.RunInterval(ctx, time.UnixMilli(upper)); err == nil {
		t.Fatal("expected failure on second page")
	}
	check(3000, 0)
	recorder.fail = false
	if err := s.RunInterval(ctx, time.UnixMilli(upper)); err != nil {
		t.Fatal(err)
	}
	check(upper, 1500)
	if err := s.RunInterval(ctx, time.UnixMilli(upper+1000)); err != nil {
		t.Fatal(err)
	}
	check(upper+1000, 5000)
	recorder.older, recorder.fail = true, true
	if err := s.RunInterval(ctx, time.UnixMilli(upper+2000)); err == nil {
		t.Fatal("expected failure after rollback")
	}
	check(upper+1000, 1700)
	recorder.fail = false
	if err := s.RunInterval(ctx, time.UnixMilli(upper+2000)); err != nil {
		t.Fatal(err)
	}
	check(upper+2000, 1700)
	if err := s.RunInterval(ctx, time.UnixMilli(upper+3000)); err != nil {
		t.Fatal(err)
	}
	check(upper+3000, 7000)
}
