package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type UserRule struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	AppID     string `json:"app_id"`
	Match     string `json:"match"`
	Exclude   bool   `json:"exclude"`
	Priority  int    `json:"priority"`
	UpdatedMS int64  `json:"updated_ms"`
}

// Rules are stored separately from bundled rules, so upgrades preserve them.
func (s *Store) EnsureRules(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS user_domain_rules(id INTEGER PRIMARY KEY AUTOINCREMENT,domain TEXT NOT NULL,app_id TEXT NOT NULL,match_type TEXT NOT NULL,excluded INTEGER NOT NULL,priority INTEGER NOT NULL,updated_ms INTEGER NOT NULL);
		CREATE INDEX IF NOT EXISTS user_domain_rules_definition ON user_domain_rules(domain,app_id,match_type,excluded,priority)`)
	return err
}
func (s *Store) UserRules(ctx context.Context) ([]UserRule, error) {
	if err := s.EnsureRules(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,domain,app_id,match_type,excluded,priority,updated_ms FROM user_domain_rules ORDER BY priority DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UserRule{}
	for rows.Next() {
		var v UserRule
		if err := rows.Scan(&v.ID, &v.Domain, &v.AppID, &v.Match, &v.Exclude, &v.Priority, &v.UpdatedMS); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func validDomain(v string) bool {
	if len(v) < 1 || len(v) > 253 || strings.ContainsAny(v, " /:*?@\\\t\r\n") {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func normalizedUserRule(v UserRule) (UserRule, error) {
	v.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v.Domain), "."))
	v.AppID = strings.TrimSpace(v.AppID)
	if !validDomain(v.Domain) || (v.Match != "exact" && v.Match != "suffix") || (!v.Exclude && v.AppID == "") || len(v.AppID) > 100 || v.Priority < -10000 || v.Priority > 10000 {
		return v, errors.New("invalid rule")
	}
	return v, nil
}
func (s *Store) SaveUserRule(ctx context.Context, v UserRule) (UserRule, error) {
	if err := s.EnsureRules(ctx); err != nil {
		return v, err
	}
	v, err := normalizedUserRule(v)
	if err != nil {
		return v, err
	}
	v.UpdatedMS = time.Now().UnixMilli()
	if v.ID == 0 {
		res, err := s.db.ExecContext(ctx, `INSERT INTO user_domain_rules(domain,app_id,match_type,excluded,priority,updated_ms) VALUES(?,?,?,?,?,?)`, v.Domain, v.AppID, v.Match, v.Exclude, v.Priority, v.UpdatedMS)
		if err != nil {
			return v, err
		}
		v.ID, err = res.LastInsertId()
		return v, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE user_domain_rules SET domain=?,app_id=?,match_type=?,excluded=?,priority=?,updated_ms=? WHERE id=?`, v.Domain, v.AppID, v.Match, v.Exclude, v.Priority, v.UpdatedMS, v.ID)
	if err != nil {
		return v, err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return v, sql.ErrNoRows
	}
	return v, err
}
func (s *Store) DeleteUserRule(ctx context.Context, id int64) error {
	if err := s.EnsureRules(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_domain_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}
