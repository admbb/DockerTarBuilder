package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestDomainMigrationPreservesAndBacksUpExistingData(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "netflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.db.Exec(`INSERT INTO dests(id,key,kind,label) VALUES(1,'d:example.com','domain','example.com'); INSERT INTO rollup_1h(ts,dev,dest,svc,zone,up,down,up_pk,down_pk,conns) VALUES(1,2,1,3,0,10,20,0,0,1)`); err != nil {
		t.Fatal(err)
	}
	backup, err := st.MigrateDomainIntelligence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(backup); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", "file:"+filepath.ToSlash(backup))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	for _, db := range []*sql.DB{old, st.db} {
		var up, down int
		if err = db.QueryRow(`SELECT up,down FROM rollup_1h WHERE dest=1`).Scan(&up, &down); err != nil || up != 10 || down != 20 {
			t.Fatalf("traffic changed: %d %d %v", up, down, err)
		}
	}
	again, err := st.MigrateDomainIntelligence(context.Background())
	if err != nil || again != "" {
		t.Fatalf("repeat migration: %q %v", again, err)
	}
}
