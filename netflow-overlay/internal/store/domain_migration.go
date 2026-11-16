package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// MigrateDomainIntelligence creates isolated tables without modifying the old
// traffic schema. It takes an SQLite-consistent backup before first migration.
// A caller must explicitly opt in; opening an existing DB alone does not run it.
func (s *Store) MigrateDomainIntelligence(ctx context.Context) (string, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='domain_schema'`).Scan(&exists); err != nil {
		return "", err
	}
	if exists != 0 {
		var version int
		if err := s.db.QueryRowContext(ctx, `SELECT version FROM domain_schema WHERE id=1`).Scan(&version); err != nil {
			return "", err
		}
		if version == 1 {
			return "", nil
		}
		return "", fmt.Errorf("unsupported domain schema version %d", version)
	}
	dir := filepath.Dir(s.path)
	// A unique path avoids replacing an existing user's backup. SQLite creates
	// the copy consistently even while the database uses WAL.
	f, err := os.CreateTemp(dir, "netflow-pre-domain-*.sqlite")
	if err != nil {
		return "", err
	}
	backup := f.Name()
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Remove(backup); err != nil {
		return "", err
	}
	if _, err = s.db.ExecContext(ctx, `VACUUM INTO ?`, backup); err != nil {
		return "", fmt.Errorf("domain backup: %w", err)
	}
	if err = os.Chmod(backup, 0o600); err != nil {
		return backup, fmt.Errorf("secure domain backup: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return backup, err
	}
	defer tx.Rollback()
	const ddl = `
CREATE TABLE domain_schema(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
CREATE TABLE app_catalog(id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, aliases TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE domain_rules(id INTEGER PRIMARY KEY, domain TEXT NOT NULL, match_type TEXT NOT NULL CHECK(match_type IN ('exact','suffix')), app_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL CHECK(action IN ('include','exclude')), priority INTEGER NOT NULL DEFAULT 0, confidence TEXT NOT NULL, source_id TEXT NOT NULL, source_version TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, notes TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE UNIQUE INDEX domain_rules_identity ON domain_rules(domain,match_type,source_id,app_id,action);
CREATE INDEX domain_rules_app ON domain_rules(app_id,enabled);
CREATE TABLE dns_name_candidates(ip TEXT NOT NULL, domain TEXT NOT NULL, seen INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', PRIMARY KEY(ip,domain)) WITHOUT ROWID;
CREATE INDEX dns_name_candidates_seen ON dns_name_candidates(seen);
CREATE TABLE domain_source_state(source_id TEXT PRIMARY KEY, version TEXT NOT NULL DEFAULT '', etag TEXT NOT NULL DEFAULT '', last_modified TEXT NOT NULL DEFAULT '', last_attempt INTEGER NOT NULL DEFAULT 0, last_success INTEGER NOT NULL DEFAULT 0, checksum TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '');
CREATE TABLE domain_update_runs(id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, added_count INTEGER NOT NULL DEFAULT 0, removed_count INTEGER NOT NULL DEFAULT 0, changed_count INTEGER NOT NULL DEFAULT 0, skipped_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', source_summary TEXT NOT NULL DEFAULT '');
CREATE TABLE domain_snapshots(id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, checksum TEXT NOT NULL, content BLOB NOT NULL);
INSERT INTO domain_schema(id,version) VALUES (1,1);`
	if _, err = tx.ExecContext(ctx, ddl); err != nil {
		return backup, fmt.Errorf("domain migration: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return backup, err
	}
	return backup, nil
}
