package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"modernc.org/sqlite"
	"netflow-plus-v2/internal/oxidns"
)

// Each AAAA produces a marker for the legacy evidence cap and, if valid,
// a canonical address for candidate retrieval.
const dnsAnswerProjection = `
	SELECT source, client_ip, event_id, created_ms, address, max(expires_ms)
	FROM (
		SELECT event.source, event.client_ip, event.event_id, event.created_ms,
		       CASE WHEN upper(json_extract(a.value,'$.rr_type'))='A'
		            THEN '4:' || json_extract(a.value,'$.payload_text')
		            WHEN kinds.exact=0 THEN '6:'
		            ELSE '6:' || nfp_dns_ipv6(json_extract(a.value,'$.payload_text')) END AS address,
		       event.created_ms + 1000*json_extract(a.value,'$.ttl') AS expires_ms
		FROM %s
		JOIN json_each(event.payload,'$.answers_json') a
		JOIN (SELECT 0 AS exact UNION ALL SELECT 1) kinds
		WHERE (upper(json_extract(a.value,'$.rr_type'))='AAAA'
		       OR (upper(json_extract(a.value,'$.rr_type'))='A' AND kinds.exact=0))
	)
	WHERE address IS NOT NULL AND expires_ms IS NOT NULL
	GROUP BY 1,2,3,4,5`

func init() {
	sqlite.MustRegisterDeterministicScalarFunction("nfp_dns_ipv6", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		data, ok := args[0].(string)
		if !ok {
			return nil, nil
		}
		ip, err := netip.ParseAddr(data)
		if err != nil || !ip.Is6() || ip.Is4In6() {
			return nil, nil
		}
		return ip.String(), nil
	})
}
func dnsAnswerSelect(from string) string {
	return fmt.Sprintf(dnsAnswerProjection, from)
}

func initDNSAnswerIndex(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`
	CREATE TABLE IF NOT EXISTS dns_answer_index(
		source TEXT NOT NULL, client_ip TEXT NOT NULL, event_id INTEGER NOT NULL,
		created_ms INTEGER NOT NULL, address TEXT NOT NULL, expires_ms INTEGER NOT NULL,
		PRIMARY KEY(source,event_id,address)
	) WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS dns_answer_index_lookup ON dns_answer_index(source,client_ip,address,expires_ms,created_ms);
	CREATE TABLE IF NOT EXISTS dns_answer_index_progress(
		id INTEGER PRIMARY KEY CHECK(id=1), source TEXT NOT NULL, event_id INTEGER NOT NULL, complete INTEGER NOT NULL
	);
	INSERT OR IGNORE INTO dns_answer_index_progress
	SELECT 1,'',0,NOT EXISTS(SELECT 1 FROM dns_events);
	CREATE TRIGGER IF NOT EXISTS dns_answer_index_prune AFTER DELETE ON dns_events BEGIN
		DELETE FROM dns_answer_index WHERE source=OLD.source AND event_id=OLD.event_id;
	END;`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`CREATE TRIGGER IF NOT EXISTS dns_answer_index_insert AFTER INSERT ON dns_events BEGIN
		INSERT INTO dns_answer_index ` + dnsAnswerSelect("(SELECT NEW.source AS source, NEW.client_ip AS client_ip, NEW.event_id AS event_id, NEW.created_ms AS created_ms, NEW.payload AS payload) event") + `;
	END;`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) runDNSAnswerBackfill(ctx context.Context) {
	var lastError string
	for {
		done, err := s.backfillDNSAnswerBatch(ctx)
		if done || ctx.Err() != nil {
			return
		}
		delay := 10 * time.Millisecond
		if err != nil {
			if err.Error() != lastError {
				log.Printf("DNS answer index backfill: %v", err)
				lastError = err.Error()
			}
			delay = time.Second
		} else {
			lastError = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *Store) backfillDNSAnswerBatch(ctx context.Context) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var source string
	var id int64
	var done bool
	if err = tx.QueryRowContext(ctx, `SELECT source,event_id,complete FROM dns_answer_index_progress WHERE id=1`).Scan(&source, &id, &done); err != nil || done {
		return done, err
	}
	const batchSize = 2048
	var lastSource string
	var lastID int64
	err = tx.QueryRowContext(ctx, `
		SELECT source,event_id FROM (
			SELECT source,event_id FROM dns_events WHERE (source,event_id)>(?,?) ORDER BY source,event_id LIMIT ?
		) ORDER BY source DESC,event_id DESC LIMIT 1`, source, id, batchSize).Scan(&lastSource, &lastID)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `UPDATE dns_answer_index_progress SET complete=1 WHERE id=1`)
		if err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO dns_answer_index `+dnsAnswerSelect("(SELECT * FROM dns_events WHERE (source,event_id)>(?,?) AND (source,event_id)<=(?,?)) event"), source, id, lastSource, lastID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE dns_answer_index_progress SET source=?,event_id=? WHERE id=1`, lastSource, lastID); err != nil {
		return false, err
	}
	return false, tx.Commit()
}

func (s *Store) DNSAnswerIndexReady(ctx context.Context) (bool, error) {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT complete FROM dns_answer_index_progress WHERE id=1`).Scan(&ready)
	return ready, err
}

type DNSCorrelationQuery struct {
	Client, Remote               string
	RecentFrom, FlowStart, Until int64
}

// DNSCorrelationBatch uses one read per page. Each result retains the same
// exhaustion threshold. It loads only responses that could mention the remote.
// A nil result marks a query that exceeded the limit.
func (s *Store) DNSCorrelationBatch(ctx context.Context, source string, queries []DNSCorrelationQuery) ([][]oxidns.Record, error) {
	out := make([][]oxidns.Record, len(queries))
	if len(queries) == 0 {
		return out, nil
	}
	input := make([][7]any, len(queries))
	for i, q := range queries {
		client, err := netip.ParseAddr(q.Client)
		if err != nil {
			return nil, errors.New("invalid client IP")
		}
		remote, _ := netip.ParseAddr(q.Remote)
		v6 := ""
		address := "4:" + remote.Unmap().String()
		matchAddress := address
		if remote.Unmap().Is6() {
			v6 = "6:"
			matchAddress = v6 + remote.Unmap().String()
		}
		input[i] = [7]any{client.Unmap().String(), address, v6, matchAddress, q.RecentFrom, q.FlowStart, q.Until}
	}
	params, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	// Per-client time bounds let a page share the count of recent events and
	// live historical AAAA markers. Near the cap, count each flow precisely.
	rows, err := s.db.QueryContext(ctx, `
		WITH q AS MATERIALIZED (
			SELECT key AS n, value->>0 AS client, value->>1 AS address, value->>2 AS v6,
			       value->>3 AS match_address, value->>4 AS recent, value->>5 AS start, value->>6 AS until
			FROM json_each(?)
		),
		client_windows AS (
			SELECT client,min(recent) AS lo,max(until) AS hi,min(start) AS earliest,max(recent) AS latest,
			       max(v6) AS v6
			FROM q GROUP BY client
		),
		client_bounds AS MATERIALIZED (
			SELECT w.client, (
				SELECT count(*) FROM (
					SELECT event_id FROM dns_events INDEXED BY dns_events_client_time
					WHERE source=?2 AND client_ip=w.client AND created_ms BETWEEN w.lo AND w.hi
					LIMIT 10001
				)
			) + (
				SELECT count(*) FROM (
					SELECT event_id FROM dns_answer_index INDEXED BY dns_answer_index_lookup
					WHERE source=?2 AND client_ip=w.client AND address=w.v6
					  AND expires_ms>w.earliest AND created_ms<w.latest
					LIMIT 10001
				)
			) AS upper_bound
			FROM client_windows w
		)
		SELECT n, CASE WHEN CASE WHEN b.upper_bound + (
			SELECT count(*) FROM (
				SELECT event_id FROM dns_answer_index INDEXED BY dns_answer_index_lookup
				WHERE source=?2 AND client_ip=q.client AND address=q.address
				  AND expires_ms>q.start AND created_ms<q.recent
				LIMIT 10001
			)
		) <= 10000 THEN 0 ELSE (
			SELECT count(*) FROM (
				SELECT event_id FROM dns_events INDEXED BY dns_events_client_time
				WHERE source=?2 AND client_ip=q.client AND created_ms>=q.recent AND created_ms<=q.until
				LIMIT 10001
			)
		) + (
			SELECT count(*) FROM (
				SELECT DISTINCT event_id FROM dns_answer_index INDEXED BY dns_answer_index_lookup
				WHERE source=?2 AND client_ip=q.client AND address IN (q.address,q.v6)
				  AND expires_ms>q.start AND created_ms<q.recent AND created_ms>=0
				LIMIT 10001
			)
		) > 10000 END THEN 'null' ELSE (
			SELECT json_group_array(payload) FROM (
				SELECT e.payload FROM dns_answer_index a INDEXED BY dns_answer_index_lookup
				JOIN dns_events e ON e.source=a.source AND e.event_id=a.event_id
				WHERE a.source=?2 AND a.client_ip=q.client AND a.address=q.match_address
				  AND a.expires_ms>q.start AND a.created_ms<=q.until AND a.created_ms>=0
			)
		) END FROM q JOIN client_bounds b USING (client)`, string(params), source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	decoded := make(map[string]oxidns.Record)
	for rows.Next() {
		var i int
		var payload string
		if err := rows.Scan(&i, &payload); err != nil {
			return nil, err
		}
		var records []string
		if err := json.Unmarshal([]byte(payload), &records); err != nil {
			return nil, err
		}
		if records == nil {
			continue
		}
		out[i] = make([]oxidns.Record, len(records))
		for j, record := range records {
			saved, ok := decoded[record]
			if !ok {
				if err := json.Unmarshal([]byte(record), &saved); err != nil {
					return nil, err
				}
				decoded[record] = saved
			}
			out[i][j] = saved
		}
	}
	return out, rows.Err()
}
