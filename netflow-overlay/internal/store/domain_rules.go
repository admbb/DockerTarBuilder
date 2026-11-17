package store

import (
	"errors"
	"fmt"
	"time"
)

// UserDomainRule is a user-owned rule; automatic sources never overwrite it.
type UserDomainRule struct {
	ID      int64  `json:"id"`
	Domain  string `json:"domain"`
	Match   string `json:"match"`
	AppID   string `json:"appId"`
	Exclude bool   `json:"exclude"`
	Enabled bool   `json:"enabled"`
}

var ErrDomainRuleNotFound = errors.New("domain rule not found")

func (s *Store) LoadUserDomainRules() ([]UserDomainRule, error) {
	rows, err := s.db.Query(`SELECT id,domain,match_type,app_id,action,enabled FROM domain_rules WHERE source_id='user' ORDER BY domain,match_type,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]UserDomainRule, 0)
	for rows.Next() {
		var r UserDomainRule
		var action string
		if err := rows.Scan(&r.ID, &r.Domain, &r.Match, &r.AppID, &action, &r.Enabled); err != nil {
			return nil, err
		}
		r.Exclude = action == "exclude"
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveUserDomainRule(r UserDomainRule) (int64, error) {
	action := "include"
	if r.Exclude {
		action = "exclude"
	}
	now := time.Now().Unix()
	if r.ID == 0 {
		res, err := s.db.Exec(`INSERT INTO domain_rules(domain,match_type,app_id,action,confidence,source_id,enabled,created_at,updated_at) VALUES(?,?,?,?,'user','user',?,?,?)`, r.Domain, r.Match, r.AppID, action, r.Enabled, now, now)
		if err != nil {
			return 0, fmt.Errorf("save domain rule: %w", err)
		}
		return res.LastInsertId()
	}
	res, err := s.db.Exec(`UPDATE domain_rules SET domain=?,match_type=?,app_id=?,action=?,enabled=?,updated_at=? WHERE id=? AND source_id='user'`, r.Domain, r.Match, r.AppID, action, r.Enabled, now, r.ID)
	if err != nil {
		return 0, fmt.Errorf("save domain rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrDomainRuleNotFound
	}
	return r.ID, nil
}

func (s *Store) DeleteUserDomainRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM domain_rules WHERE id=? AND source_id='user'`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDomainRuleNotFound
	}
	return nil
}
