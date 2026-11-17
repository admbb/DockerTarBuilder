package store

import (
	"path/filepath"
	"testing"
)

func TestHistoricalDomainsUsesDomainRollupsOnly(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	batch := &Batch{Dests: []DestRow{{ID: 1, Key: "d:example.com", Kind: "domain", Label: "example.com"}, {ID: 2, Key: "app:youtube", Kind: "app", Label: "YouTube"}}, Rollups: map[RollupKey]RollupVal{{TS: 7200, Dest: 1}: {Up: 100, Down: 200, Conns: 3}, {TS: 7200, Dest: 2}: {Up: 1000, Down: 2000, Conns: 10}}}
	if err = st.Write(batch); err != nil {
		t.Fatal(err)
	}
	rows, err := st.HistoricalDomains(7200, 10800, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Domain != "example.com" || rows[0].Up != 100 || rows[0].Down != 200 || rows[0].Connections != 3 {
		t.Fatalf("unexpected: %+v", rows)
	}
	rows, err = st.HistoricalDomains(10800, 14400, 50)
	if err != nil || len(rows) != 0 {
		t.Fatalf("range: %+v %v", rows, err)
	}
}
