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
}

func (f *fakeRecorder) Records(ctx context.Context, since, until time.Time, cursor string) (oxidns.Page, error) {
	f.calls++
	if cursor == "" {
		return oxidns.Page{OK: true, NextCursor: "cursor-1", Records: []oxidns.Record{{ID: 1, CreatedAtMS: 1000, ClientIP: "192.168.1.2"}}}, nil
	}
	if f.fail {
		return oxidns.Page{}, errors.New("temporary failure")
	}
	if f.loop {
		return oxidns.Page{OK: true, NextCursor: "cursor-1"}, nil
	}
	return oxidns.Page{OK: true, Records: []oxidns.Record{{ID: 2, CreatedAtMS: 2000, ClientIP: "192.168.1.3"}}}, nil
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
