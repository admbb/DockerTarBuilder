package storage

import (
	"context"
	"errors"

	"netflow-plus-v2/internal/flow"
)

// ReceivedFlowTotals reports the exact receive-time interval used for application
// rankings. It counts retained WAN exports, including unclassified bytes.
func (s *Store) ReceivedFlowTotals(ctx context.Context, from, until int64) (FlowTotals, error) {
	var out FlowTotals
	if from < 0 || until <= from {
		return out, errors.New("invalid flow interval")
	}
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(CASE WHEN direction=0 THEN bytes ELSE 0 END),0),
		       COALESCE(SUM(CASE WHEN direction=1 THEN bytes ELSE 0 END),0), COUNT(*)
		FROM flow_segments WHERE zone=0 AND received_ms>=? AND received_ms<?`,
		from, until).Scan(&out.Up, &out.Down, &out.Records)
	return out, err
}

type TrafficSegment struct {
	ReceivedMS, StartMS, EndMS int64
	Exporter, Digest           string
	Ordinal                    int
	ClientIP, RemoteIP         string
	Proto                      uint8
	Direction                  flow.Dir
	Bytes                      uint64
	TimeQuality                string
}

const TrafficPageSize = 512

// TrafficSegments copies a bounded page so callers can query DNS evidence after
// this function releases the database connection.
func (s *Store) TrafficSegments(ctx context.Context, from, until int64, after *TrafficSegment) ([]TrafficSegment, error) {
	if from < 0 || until <= from {
		return nil, errors.New("invalid flow interval")
	}
	received, exporter, digest, ordinal := from, "", "", -1
	if after != nil {
		received, exporter, digest, ordinal = after.ReceivedMS, after.Exporter, after.Digest, after.Ordinal
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT received_ms, exporter, digest, ordinal, start_ms, end_ms, client_ip, remote_ip, proto, direction, bytes, time_quality
		FROM flow_segments
		WHERE zone=0 AND received_ms>=? AND received_ms<?
		  AND (received_ms,exporter,digest,ordinal)>(?,?,?,?)
		ORDER BY received_ms,exporter,digest,ordinal LIMIT ?`,
		from, until, received, exporter, digest, ordinal, TrafficPageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TrafficSegment, 0, TrafficPageSize)
	for rows.Next() {
		var row TrafficSegment
		if err = rows.Scan(&row.ReceivedMS, &row.Exporter, &row.Digest, &row.Ordinal, &row.StartMS,
			&row.EndMS, &row.ClientIP, &row.RemoteIP, &row.Proto, &row.Direction, &row.Bytes, &row.TimeQuality); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
