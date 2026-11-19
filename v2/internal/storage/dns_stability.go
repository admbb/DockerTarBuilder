package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DNSStability describes fully traversed local recorder scans. UntilMS is
// exclusive, and the watermark says nothing about unrecorded DNS traffic.
type DNSStability struct {
	FromMS           int64 `json:"from_ms"`
	UntilMS          int64 `json:"until_ms"`
	ScannedFromMS    int64 `json:"scanned_from_ms"`
	ScannedUntilMS   int64 `json:"scanned_until_ms"`
	CompletedAtMS    int64 `json:"completed_at_ms"`
	EvidenceRevision int64 `json:"evidence_revision"`
}

func (s *Store) DNSStability(ctx context.Context, source string) (DNSStability, error) {
	var status DNSStability
	err := s.db.QueryRowContext(ctx, `
SELECT max(d.stable_from_ms,s.started_ms),d.stable_until_ms,
       d.scanned_from_ms,d.scanned_until_ms,d.completed_at_ms,coalesce(r.revision,0)
FROM dns_stability d JOIN sync_state s USING(source)
LEFT JOIN dns_evidence_revisions r USING(source) WHERE d.source=?`, source).
		Scan(&status.FromMS, &status.UntilMS, &status.ScannedFromMS, &status.ScannedUntilMS, &status.CompletedAtMS, &status.EvidenceRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	status.UntilMS = max(status.FromMS, status.UntilMS)
	return status, err
}

func lowerDNSWatermark(ctx context.Context, tx *sql.Tx, source string, at, checkpoint int64) error {
	result, err := tx.ExecContext(ctx, `
UPDATE dns_stability SET stable_until_ms=max(stable_from_ms,?)
WHERE source=? AND stable_until_ms>max(stable_from_ms,?) AND scanned_until_ms=?`, at, source, at, checkpoint)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO dns_evidence_revisions(source,revision) VALUES(?,1)
ON CONFLICT(source) DO UPDATE SET revision=revision+1`, source)
	return err
}

// CompleteDNSScan records an audit watermark atomically with the ingestion
// checkpoint. A legacy checkpoint cannot on its own establish rescanned coverage.
func (s *Store) CompleteDNSScan(ctx context.Context, source string, expected, scannedFrom, scannedUntil, completedAt, replayLag int64) error {
	if source == "" || scannedFrom < 0 || scannedFrom > expected || scannedUntil <= expected || completedAt < scannedUntil || replayLag <= 0 {
		return errors.New("invalid DNS scan")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var start, current int64
	err = tx.QueryRowContext(ctx, `SELECT started_ms,completed_until_ms FROM sync_state WHERE source=?`, source).Scan(&start, &current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current != expected || scannedFrom < start {
		return fmt.Errorf("DNS scan coverage changed: expected checkpoint %d, got %d", expected, current)
	}
	stableFrom, stableUntil := scannedFrom, scannedFrom
	var previousFrom, previousUntil, previousScanFrom, previousScanUntil int64
	err = tx.QueryRowContext(ctx, `SELECT stable_from_ms,stable_until_ms,scanned_from_ms,scanned_until_ms FROM dns_stability WHERE source=?`, source).
		Scan(&previousFrom, &previousUntil, &previousScanFrom, &previousScanUntil)
	if err == nil && previousScanUntil == expected {
		stableFrom = max(start, previousFrom)
		stableUntil = max(stableFrom, previousUntil)
		if scannedFrom > stableUntil {
			stableFrom, stableUntil = scannedFrom, scannedFrom
		}
		replayFrom := max(scannedFrom, previousScanFrom)
		replayUntil := min(previousScanUntil, scannedUntil-replayLag)
		var firstAddition sql.NullInt64
		if err = tx.QueryRowContext(ctx, `
SELECT min(created_ms) FROM dns_scan_additions
WHERE source=? AND introduced_after_ms=? AND created_ms>=? AND created_ms<?`,
			source, expected, replayFrom, replayUntil).Scan(&firstAddition); err != nil {
			return err
		}
		if firstAddition.Valid {
			replayUntil = firstAddition.Int64
		}
		if replayFrom <= stableUntil && replayUntil > stableUntil {
			stableUntil = replayUntil
		}
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
INSERT INTO sync_state(source,completed_until_ms) VALUES(?,?)
ON CONFLICT(source) DO UPDATE SET completed_until_ms=excluded.completed_until_ms`, source, scannedUntil); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
INSERT INTO dns_stability(source,stable_from_ms,stable_until_ms,scanned_from_ms,scanned_until_ms,completed_at_ms) VALUES(?,?,?,?,?,?)
ON CONFLICT(source) DO UPDATE SET stable_from_ms=excluded.stable_from_ms,stable_until_ms=excluded.stable_until_ms,
 scanned_from_ms=excluded.scanned_from_ms,scanned_until_ms=excluded.scanned_until_ms,completed_at_ms=excluded.completed_at_ms`,
		source, stableFrom, stableUntil, scannedFrom, scannedUntil, completedAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM dns_scan_additions WHERE source=? AND introduced_after_ms<=?`, source, expected); err != nil {
		return err
	}
	return tx.Commit()
}
