package storage

import (
	"context"
	"errors"
	"strings"
)

type DomainCount struct {
	Domain  string `json:"domain"`
	Queries int64  `json:"queries"`
	Devices int64  `json:"devices"`
}

// DNSPopularity counts distinct question names per event; it never represents
// query counts as bytes. Limit truncation must be disclosed by callers.
func (s *Store) DNSPopularity(ctx context.Context, source string, from, until int64, limit int) ([]DomainCount, error) {
	if source == "" || from < 0 || until <= from || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid DNS statistics query")
	}
	// Historical rankings are hour buckets; include partial boundary hours
	// explicitly rather than claiming exact second-level counts.
	fromBucket := (from / 3600000) * 3600000
	untilBucket := ((until + 3599999) / 3600000) * 3600000
	rows, err := s.db.QueryContext(ctx, `WITH totals AS (SELECT domain,SUM(queries) AS n FROM dns_hourly WHERE source=? AND bucket_ms>=? AND bucket_ms<? GROUP BY domain), devices AS (SELECT domain,COUNT(DISTINCT client_ip) AS n FROM dns_hourly_clients WHERE source=? AND bucket_ms>=? AND bucket_ms<? GROUP BY domain) SELECT totals.domain,totals.n,COALESCE(devices.n,0) FROM totals LEFT JOIN devices USING(domain) ORDER BY totals.n DESC,totals.domain ASC LIMIT ?`, source, fromBucket, untilBucket, source, fromBucket, untilBucket, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DomainCount, 0)
	for rows.Next() {
		var row DomainCount
		if err := rows.Scan(&row.Domain, &row.Queries, &row.Devices); err != nil {
			return nil, err
		}
		row.Domain = strings.TrimSpace(row.Domain)
		result = append(result, row)
	}
	return result, rows.Err()
}
