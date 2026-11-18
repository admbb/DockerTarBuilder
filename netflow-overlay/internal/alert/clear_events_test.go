package alert

import (
	"io"
	"log/slog"
	"mikrotik-home-netflow-plus/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestClearEventsResetsActiveState(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := NewManager(st, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Now()
	m.mu.Lock()
	m.fire(now, NoExport, "", 0, "critical", "test", "")
	m.mu.Unlock()
	if m.FiringCount() != 1 {
		t.Fatal("missing active alert")
	}
	count, err := m.ClearEvents()
	if err != nil || count != 1 {
		t.Fatalf("clear %d %v", count, err)
	}
	if m.FiringCount() != 0 || len(m.Events(0, 10)) != 0 {
		t.Fatal("events or active state remain")
	}
	m.mu.Lock()
	m.fire(now.Add(time.Second), NoExport, "", 0, "critical", "test", "")
	m.mu.Unlock()
	if m.FiringCount() != 1 || len(m.Events(0, 10)) != 1 {
		t.Fatal("ongoing condition did not reappear")
	}
}
