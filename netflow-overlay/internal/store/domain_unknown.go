package store

// HistoricalDomain is a recorded domain-group destination, not an individual
// DNS query. Earlier aggregate rows are not reclassified when rules change.
type HistoricalDomain struct {
	Domain      string `json:"domain"`
	Up          uint64 `json:"up"`
	Down        uint64 `json:"down"`
	Connections uint64 `json:"connections"`
}

func (s *Store) HistoricalDomains(from, to int64, limit int) ([]HistoricalDomain, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT d.label,SUM(r.up),SUM(r.down),SUM(r.conns) FROM rollup_1h r JOIN dests d ON d.id=r.dest WHERE d.kind='domain' AND r.ts>=? AND r.ts<? GROUP BY d.id,d.label ORDER BY SUM(r.up)+SUM(r.down) DESC,d.label ASC LIMIT ?`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]HistoricalDomain, 0)
	for rows.Next() {
		var r HistoricalDomain
		if err = rows.Scan(&r.Domain, &r.Up, &r.Down, &r.Connections); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
