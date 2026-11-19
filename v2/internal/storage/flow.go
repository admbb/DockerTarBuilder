package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"netflow-plus-v2/internal/flow"
)

// SaveFlowMessage atomically deduplicates a complete IPFIX datagram and adds
// its decoded delta counters to the hour in which it was received. This is an
// observed export interval, not a claim about exact per-packet timing.
func (s *Store) SaveFlowMessage(ctx context.Context, exporter netip.Addr, digest [32]byte, received time.Time, flows []flow.Flow, domain uint32, sequence uint32, recordCount uint32) (bool, error) {
	return s.saveFlowMessage(ctx, exporter, digest, received, flows, domain, sequence, recordCount, nil)
}

func (s *Store) saveFlowMessage(ctx context.Context, exporter netip.Addr, digest [32]byte, received time.Time, flows []flow.Flow, domain, sequence, recordCount uint32, packet *IPFIXPacket) (bool, error) {
	if !exporter.IsValid() || received.IsZero() {
		return false, errors.New("invalid flow message")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// The legacy entry point has no boot identity and therefore keeps guarding
	// modulo sequence positions for the lifetime of its ledger.
	if packet != nil {
		duplicate, err := recordIPFIXSequence(ctx, tx, exporter.Unmap().String(), hex.EncodeToString(digest[:]), *packet)
		if duplicate || err != nil {
			return false, err
		}
	} else if recordCount > 0 {
		key := hex.EncodeToString(digest[:])
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO flow_sequences(exporter,observation_domain,sequence,digest) VALUES(?,?,?,?)`, exporter.Unmap().String(), domain, sequence, key)
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if n == 0 {
			var existing string
			if err = tx.QueryRowContext(ctx, `SELECT digest FROM flow_sequences WHERE exporter=? AND observation_domain=? AND sequence=?`, exporter.Unmap().String(), domain, sequence).Scan(&existing); err != nil {
				return false, err
			}
			if existing != key {
				return false, errors.New("IPFIX sequence conflict; exporter epoch or retransmission uncertain")
			}
			// The sequence ledger is retained longer than raw messages. An
			// exact replay must stay deduplicated even after message pruning.
			return false, tx.Commit()
		}
		const wrap uint64 = 1 << 32
		start, end := uint64(sequence), uint64(sequence)+uint64(recordCount)
		ranges := [][2]uint64{{start, min(end, wrap)}}
		if end > wrap {
			ranges = append(ranges, [2]uint64{0, end - wrap})
		}
		for _, interval := range ranges {
			var existing string
			var previousEnd uint64
			err := tx.QueryRowContext(ctx, `SELECT end_seq,digest FROM flow_sequence_ranges WHERE exporter=? AND observation_domain=? AND start_seq<=? ORDER BY start_seq DESC LIMIT 1`, exporter.Unmap().String(), domain, interval[0]).Scan(&previousEnd, &existing)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return false, err
			}
			if err == nil && previousEnd > interval[0] && existing != key {
				return false, errors.New("overlapping IPFIX sequence range; data rejected")
			}
			err = tx.QueryRowContext(ctx, `SELECT digest FROM flow_sequence_ranges WHERE exporter=? AND observation_domain=? AND start_seq>? AND start_seq<? ORDER BY start_seq LIMIT 1`, exporter.Unmap().String(), domain, interval[0], interval[1]).Scan(&existing)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return false, err
			}
			if err == nil && existing != key {
				return false, errors.New("overlapping IPFIX sequence range; data rejected")
			}
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO flow_sequence_ranges(exporter,observation_domain,start_seq,end_seq,digest) VALUES(?,?,?,?,?)`, exporter.Unmap().String(), domain, interval[0], interval[1], key); err != nil {
				return false, err
			}
		}
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO flow_messages(exporter,digest,received_ms) VALUES(?,?,?)`, exporter.Unmap().String(), hex.EncodeToString(digest[:]), received.UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, tx.Commit()
	}
	bucket := (received.UnixMilli() / 3600000) * 3600000
	for ordinal, f := range flows {
		if !f.LocalIP.IsValid() || f.Bytes > math.MaxInt64 || f.Dir > flow.Down {
			return false, errors.New("invalid decoded flow")
		}
		if !f.RemoteIP.IsValid() {
			return false, errors.New("invalid remote IP")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO flow_segments(exporter,digest,ordinal,received_ms,start_ms,end_ms,client_ip,remote_ip,local_port,remote_port,proto,direction,zone,bytes,time_quality) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, exporter.Unmap().String(), hex.EncodeToString(digest[:]), ordinal, received.UnixMilli(), f.Start.UnixMilli(), f.End.UnixMilli(), f.LocalIP.Unmap().String(), f.RemoteIP.Unmap().String(), f.LocalPort, f.RemotePort, f.Proto, uint8(f.Dir), uint8(f.Zone), f.Bytes, f.TimeQuality); err != nil {
			return false, err
		}
		var up, down uint64
		if f.Dir == flow.Up {
			up = f.Bytes
		} else {
			down = f.Bytes
		}
		res, err = tx.ExecContext(ctx, `INSERT INTO flow_hourly(exporter,bucket_ms,client_ip,zone,up,down,records) VALUES(?,?,?,?,?,?,1) ON CONFLICT(exporter,bucket_ms,client_ip,zone) DO UPDATE SET up=up+excluded.up,down=down+excluded.down,records=records+1 WHERE up<=9223372036854775807-excluded.up AND down<=9223372036854775807-excluded.down AND records<9223372036854775807`, exporter.Unmap().String(), bucket, f.LocalIP.Unmap().String(), uint8(f.Zone), up, down)
		if err != nil {
			return false, err
		}
		updated, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		if updated != 1 {
			return false, fmt.Errorf("flow counter overflow")
		}
	}
	return true, tx.Commit()
}

// PruneFlowBefore prunes V2 traffic data but retains sequence ledgers so old
// UDP replays cannot be added back after retention cleanup.
func (s *Store) PruneFlowBefore(ctx context.Context, cutoff int64) error {
	if cutoff <= 0 {
		return errors.New("invalid flow retention cutoff")
	}
	cutoff = (cutoff / 3600000) * 3600000
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM flow_segments WHERE received_ms<?`, `DELETE FROM flow_messages WHERE received_ms<?`, `DELETE FROM flow_hourly WHERE bucket_ms<?`} {
		if _, err = tx.ExecContext(ctx, q, cutoff); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type FlowTotals struct {
	Up      uint64 `json:"up"`
	Down    uint64 `json:"down"`
	Records uint64 `json:"records"`
}

// FlowMessageSeen lets the collector reject an exact replay before it can
// alter its in-memory template or clock state.
func (s *Store) FlowMessageSeen(ctx context.Context, exporter netip.Addr, digest [32]byte) (bool, error) {
	return flowMessageSeen(ctx, s.db, exporter.Unmap().String(), hex.EncodeToString(digest[:]))
}

type FlowHealth struct {
	Messages       int64 `json:"messages"`
	LastReceivedMS int64 `json:"last_received_ms"`
}

func (s *Store) FlowHealth(ctx context.Context) (FlowHealth, error) {
	var out FlowHealth
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MAX(received_ms),0) FROM flow_messages`).Scan(&out.Messages, &out.LastReceivedMS)
	return out, err
}

func (s *Store) FlowTotals(ctx context.Context, from, until int64) (FlowTotals, error) {
	var out FlowTotals
	if from < 0 || until <= from {
		return out, errors.New("invalid flow interval")
	}
	from = (from / 3600000) * 3600000
	until = ((until + 3599999) / 3600000) * 3600000
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0),COALESCE(SUM(records),0) FROM flow_hourly WHERE zone=0 AND bucket_ms>=? AND bucket_ms<?`, from, until).Scan(&out.Up, &out.Down, &out.Records)
	return out, err
}
