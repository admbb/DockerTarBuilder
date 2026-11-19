package storage

import (
	"context"
	"errors"
	"sort"
)

// ReceivedTrafficDevices groups retained WAN flow segments by their LAN IP.
func (s *Store) ReceivedTrafficDevices(ctx context.Context, from, until int64) ([]TrafficDevice, error) {
	if from < 0 || until <= from {
		return nil, errors.New("invalid flow interval")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT client_ip, SUM(CASE WHEN direction=0 THEN bytes ELSE 0 END),
		       SUM(CASE WHEN direction=1 THEN bytes ELSE 0 END), COUNT(*)
		FROM flow_segments WHERE zone=0 AND received_ms>=? AND received_ms<?
		GROUP BY client_ip`, from, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TrafficDevice, 0)
	for rows.Next() {
		var device TrafficDevice
		if err = rows.Scan(&device.IP, &device.Up, &device.Down, &device.Records); err != nil {
			return nil, err
		}
		device.Bytes = device.Up + device.Down
		out = append(out, device)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].IP < out[j].IP
	})
	return out, rows.Err()
}

type TrafficDevice struct {
	IP    string `json:"ip"`
	Bytes uint64 `json:"bytes"`
	FlowTotals
}
