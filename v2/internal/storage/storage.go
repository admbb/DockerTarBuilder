package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	_ "modernc.org/sqlite"
	"netflow-plus-v2/internal/oxidns"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	const schema = `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS dns_events(source TEXT NOT NULL, event_id INTEGER NOT NULL, created_ms INTEGER NOT NULL, client_ip TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(source,event_id)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS dns_events_client_time ON dns_events(client_ip,created_ms);
 CREATE INDEX IF NOT EXISTS dns_events_source_time ON dns_events(source,created_ms);
 CREATE TABLE IF NOT EXISTS dns_hourly(source TEXT NOT NULL, bucket_ms INTEGER NOT NULL, domain TEXT NOT NULL, queries INTEGER NOT NULL, PRIMARY KEY(source,bucket_ms,domain)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS dns_hourly_clients(source TEXT NOT NULL, bucket_ms INTEGER NOT NULL, domain TEXT NOT NULL, client_ip TEXT NOT NULL, PRIMARY KEY(source,bucket_ms,domain,client_ip)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS aggregate_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS flow_messages(exporter TEXT NOT NULL, digest TEXT NOT NULL, received_ms INTEGER NOT NULL, PRIMARY KEY(exporter,digest)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS flow_sequences(exporter TEXT NOT NULL, observation_domain INTEGER NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(exporter,observation_domain,sequence)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS flow_sequence_ranges(exporter TEXT NOT NULL, observation_domain INTEGER NOT NULL, start_seq INTEGER NOT NULL, end_seq INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(exporter,observation_domain,start_seq)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS flow_sequences_digest ON flow_sequences(exporter,digest);
 CREATE TABLE IF NOT EXISTS ipfix_sessions(exporter TEXT NOT NULL, domain INTEGER NOT NULL, boot_ms INTEGER NOT NULL, export_time INTEGER NOT NULL, next_seq INTEGER NOT NULL, wrap_time INTEGER NOT NULL, legacy INTEGER NOT NULL, PRIMARY KEY(exporter,domain)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS ipfix_ranges(exporter TEXT NOT NULL, domain INTEGER NOT NULL, boot_ms INTEGER NOT NULL, start_seq INTEGER NOT NULL, end_seq INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(exporter,domain,boot_ms,start_seq)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS ipfix_ranges_digest ON ipfix_ranges(exporter,digest);
 CREATE TABLE IF NOT EXISTS flow_segments(exporter TEXT NOT NULL, digest TEXT NOT NULL, ordinal INTEGER NOT NULL, received_ms INTEGER NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER NOT NULL, client_ip TEXT NOT NULL, remote_ip TEXT NOT NULL, local_port INTEGER NOT NULL, remote_port INTEGER NOT NULL, proto INTEGER NOT NULL, direction INTEGER NOT NULL, zone INTEGER NOT NULL, bytes INTEGER NOT NULL, time_quality TEXT NOT NULL, app_id TEXT NOT NULL DEFAULT '', attribution_reason TEXT NOT NULL DEFAULT 'pending', evidence TEXT NOT NULL DEFAULT '', PRIMARY KEY(exporter,digest,ordinal)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS flow_segments_received ON flow_segments(received_ms);
 CREATE TABLE IF NOT EXISTS flow_hourly(exporter TEXT NOT NULL, bucket_ms INTEGER NOT NULL, client_ip TEXT NOT NULL, zone INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, records INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(exporter,bucket_ms,client_ip,zone)) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS sync_state(source TEXT PRIMARY KEY, started_ms INTEGER NOT NULL DEFAULT 0, completed_until_ms INTEGER NOT NULL) WITHOUT ROWID;`
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	var columnCount int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('sync_state') WHERE name='started_ms'`).Scan(&columnCount); err != nil {
		db.Close()
		return nil, err
	}
	if columnCount == 0 {
		// Older development databases lacked a lower coverage bound. Treat
		// their previous sync as starting at the epoch, as it did originally.
		if _, err = db.Exec(`ALTER TABLE sync_state ADD COLUMN started_ms INTEGER NOT NULL DEFAULT 0`); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = backfillDNSAggregates(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

func backfillDNSAggregates(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM aggregate_meta WHERE id=1`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return tx.Commit()
	}
	const events = `SELECT DISTINCT d.source,d.event_id,(d.created_ms/3600000)*3600000 AS bucket_ms,d.client_ip,lower(rtrim(trim(json_extract(j.value,'$.name')),'.')) AS domain FROM dns_events d JOIN json_each(d.payload,'$.questions_json') j WHERE json_extract(j.value,'$.name') IS NOT NULL`
	if _, err = tx.Exec(`INSERT INTO dns_hourly(source,bucket_ms,domain,queries) SELECT source,bucket_ms,domain,COUNT(*) FROM (` + events + `) WHERE domain<>'' GROUP BY source,bucket_ms,domain`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO dns_hourly_clients(source,bucket_ms,domain,client_ip) SELECT source,bucket_ms,domain,client_ip FROM (` + events + `) WHERE domain<>''`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO aggregate_meta(id,version) VALUES(1,1)`); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Close() error { return s.db.Close() }

// InitializeSource sets an explicit historical lower bound once, without
// overwriting an existing source's progress.
func (s *Store) InitializeSource(ctx context.Context, source string, start int64) error {
	if source == "" || start <= 0 {
		return errors.New("invalid source start")
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO sync_state(source,started_ms,completed_until_ms) VALUES(?,?,?)`, source, start, start)
	return err
}

func (s *Store) Coverage(ctx context.Context, source string) (int64, int64, error) {
	var start, end int64
	err := s.db.QueryRowContext(ctx, `SELECT started_ms,completed_until_ms FROM sync_state WHERE source=?`, source).Scan(&start, &end)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	return start, end, err
}

// PruneDNSBefore removes only V2's own data, at an hour boundary, and updates
// the declared coverage so pruned evidence cannot be mistaken for absence.
func (s *Store) PruneDNSBefore(ctx context.Context, source string, cutoff int64) error {
	if source == "" || cutoff <= 0 {
		return errors.New("invalid retention cutoff")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var start, end int64
	if err = tx.QueryRowContext(ctx, `SELECT started_ms,completed_until_ms FROM sync_state WHERE source=?`, source).Scan(&start, &end); err != nil {
		return err
	}
	cutoff = (min(cutoff, end) / 3600000) * 3600000
	if cutoff <= start {
		return tx.Commit()
	}
	for _, query := range []string{`DELETE FROM dns_events WHERE source=? AND created_ms<?`, `DELETE FROM dns_hourly WHERE source=? AND bucket_ms<?`, `DELETE FROM dns_hourly_clients WHERE source=? AND bucket_ms<?`} {
		if _, err = tx.ExecContext(ctx, query, source, cutoff); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sync_state SET started_ms=? WHERE source=?`, cutoff, source); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Checkpoint(ctx context.Context, source string) (int64, error) {
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT completed_until_ms FROM sync_state WHERE source=?`, source).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return ts, err
}

// EventsForClient returns all recorded observations for a client and time
// window. Truncation is an error, since missing observations could conceal
// ambiguity on a shared IP.
func (s *Store) EventsForClient(ctx context.Context, source, clientIP string, from, until int64, limit int) ([]oxidns.Record, error) {
	if source == "" || from < 0 || until < from || limit < 1 || limit > 10000 {
		return nil, errors.New("invalid evidence query")
	}
	client, err := netip.ParseAddr(clientIP)
	if err != nil {
		return nil, errors.New("invalid client IP")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM dns_events WHERE source=? AND client_ip=? AND created_ms>=? AND created_ms<=? ORDER BY created_ms,event_id LIMIT ?`, source, client.Unmap().String(), from, until, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]oxidns.Record, 0)
	for rows.Next() {
		if len(result) >= limit {
			return nil, errors.New("DNS evidence limit exceeded")
		}
		var payload string
		var record oxidns.Record
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

// SavePage is idempotent. Reusing an event ID with different source content
// fails closed instead of silently counting or overwriting a different event.
func (s *Store) SavePage(ctx context.Context, source string, records []oxidns.Record) error {
	if source == "" || len(source) > 128 {
		return errors.New("invalid source")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range records {
		if r.ID <= 0 || r.CreatedAtMS <= 0 {
			return errors.New("invalid event identity")
		}
		client, err := netip.ParseAddr(r.ClientIP)
		if err != nil {
			return fmt.Errorf("invalid DNS client IP")
		}
		r.ClientIP = client.Unmap().String()
		payload, err := json.Marshal(r)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO dns_events(source,event_id,created_ms,client_ip,payload) VALUES(?,?,?,?,?)`, source, r.ID, r.CreatedAtMS, r.ClientIP, string(payload))
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			var existing string
			if err = tx.QueryRowContext(ctx, `SELECT payload FROM dns_events WHERE source=? AND event_id=?`, source, r.ID).Scan(&existing); err != nil {
				return err
			}
			if existing != string(payload) {
				return fmt.Errorf("DNS event identity conflict: %s/%d", source, r.ID)
			}
		} else {
			bucket := (r.CreatedAtMS / 3600000) * 3600000
			seen := make(map[string]bool)
			for _, q := range r.Questions {
				name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q.Name), "."))
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				if _, err = tx.ExecContext(ctx, `INSERT INTO dns_hourly(source,bucket_ms,domain,queries) VALUES(?,?,?,1) ON CONFLICT(source,bucket_ms,domain) DO UPDATE SET queries=queries+1`, source, bucket, name); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO dns_hourly_clients(source,bucket_ms,domain,client_ip) VALUES(?,?,?,?)`, source, bucket, name, r.ClientIP); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}
func (s *Store) CompleteInterval(ctx context.Context, source string, from, until int64) error {
	if source == "" || from < 0 || until <= from {
		return errors.New("invalid sync interval")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT completed_until_ms FROM sync_state WHERE source=?`, source).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current != from {
		return fmt.Errorf("checkpoint changed: expected %d, got %d", from, current)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sync_state(source,completed_until_ms) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET completed_until_ms=excluded.completed_until_ms`, source, until)
	if err != nil {
		return err
	}
	return tx.Commit()
}
