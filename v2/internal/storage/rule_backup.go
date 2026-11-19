package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"netflow-plus-v2/internal/catalog"
	"time"
)

// RuleDefinition is portable across installations and omits database row IDs.
type RuleDefinition struct {
	Domain   string `json:"domain"`
	AppID    string `json:"app_id"`
	Match    string `json:"match"`
	Exclude  bool   `json:"exclude"`
	Priority int    `json:"priority"`
}

type RuleBackup struct {
	Version int              `json:"version"`
	Apps    []catalog.App    `json:"apps"`
	Rules   []RuleDefinition `json:"rules"`
}

type RuleImportResult struct {
	AppsAdded    int `json:"apps_added"`
	RulesAdded   int `json:"rules_added"`
	RulesSkipped int `json:"rules_skipped"`
}

var ErrInvalidRuleBackup = errors.New("invalid rule backup")
var ErrAppConflict = errors.New("conflicting application ID")

func (s *Store) ExportRuleBackup(ctx context.Context) (RuleBackup, error) {
	backup := RuleBackup{Version: 1, Rules: []RuleDefinition{}}
	rules, err := s.UserRules(ctx)
	if err != nil {
		return backup, err
	}
	for _, rule := range rules {
		backup.Rules = append(backup.Rules, RuleDefinition{rule.Domain, rule.AppID, rule.Match, rule.Exclude, rule.Priority})
	}
	backup.Apps, err = s.CustomApps(ctx)
	return backup, err
}

func (s *Store) ImportRuleBackup(ctx context.Context, backup RuleBackup, builtin []catalog.App) (RuleImportResult, error) {
	if backup.Version != 1 || backup.Apps == nil || backup.Rules == nil {
		return RuleImportResult{}, ErrInvalidRuleBackup
	}
	return s.importRuleBackup(ctx, backup.Apps, backup.Rules, builtin, true)
}

func (s *Store) importRuleBackup(ctx context.Context, apps []catalog.App, rules []RuleDefinition, builtin []catalog.App, merge bool) (RuleImportResult, error) {
	var result RuleImportResult
	if err := s.ensureCustomApps(ctx); err != nil {
		return result, err
	}
	if err := s.EnsureRules(ctx); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	builtinIDs := make(map[string]bool, len(builtin))
	for _, app := range builtin {
		builtinIDs[app.ID] = true
	}
	for _, app := range apps {
		app, err = normalizedCustomApp(app)
		if err != nil {
			return RuleImportResult{}, fmt.Errorf("%w: app %q", ErrInvalidRuleBackup, app.ID)
		}
		inserted, err := insertBackupApp(ctx, tx, app, merge)
		if err != nil {
			return RuleImportResult{}, err
		}
		if inserted {
			if builtinIDs[app.ID] {
				return RuleImportResult{}, fmt.Errorf("%w: %s", ErrAppConflict, app.ID)
			}
			result.AppsAdded++
		}
	}
	now := time.Now().UnixMilli()
	for index, rule := range rules {
		v, err := normalizedUserRule(UserRule{Domain: rule.Domain, AppID: rule.AppID, Match: rule.Match, Exclude: rule.Exclude, Priority: rule.Priority})
		if err != nil {
			return RuleImportResult{}, fmt.Errorf("%w: rule %d", ErrInvalidRuleBackup, index+1)
		}
		if !v.Exclude && !builtinIDs[v.AppID] {
			var found int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM custom_apps WHERE id=?`, v.AppID).Scan(&found)
			if errors.Is(err, sql.ErrNoRows) {
				return RuleImportResult{}, fmt.Errorf("%w: rule %d references an unknown app", ErrInvalidRuleBackup, index+1)
			}
			if err != nil {
				return RuleImportResult{}, err
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO user_domain_rules(domain,app_id,match_type,excluded,priority,updated_ms)
			SELECT ?,?,?,?,?,? WHERE NOT EXISTS (
				SELECT 1 FROM user_domain_rules WHERE domain=? AND app_id=? AND match_type=? AND excluded=? AND priority=?)`,
			v.Domain, v.AppID, v.Match, v.Exclude, v.Priority, now, v.Domain, v.AppID, v.Match, v.Exclude, v.Priority)
		if err != nil {
			return RuleImportResult{}, err
		}
		added, err := res.RowsAffected()
		if err != nil {
			return RuleImportResult{}, err
		}
		result.RulesAdded += int(added)
		result.RulesSkipped += 1 - int(added)
	}
	if err := tx.Commit(); err != nil {
		return RuleImportResult{}, err
	}
	return result, nil
}

func insertBackupApp(ctx context.Context, tx *sql.Tx, app catalog.App, merge bool) (bool, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO custom_apps(id,name,category) VALUES(?,?,?) ON CONFLICT(id) DO NOTHING`, app.ID, app.Name, app.Category)
	if err != nil {
		return false, err
	}
	added, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if added == 0 {
		var existing catalog.App
		existing.ID = app.ID
		err := tx.QueryRowContext(ctx, `SELECT a.name,a.category,COALESCE(i.icon,'') FROM custom_apps a LEFT JOIN custom_app_icons i ON i.app_id=a.id WHERE a.id=?`, app.ID).
			Scan(&existing.Name, &existing.Category, &existing.Icon)
		if err != nil {
			return false, err
		}
		if !merge || app != existing {
			return false, fmt.Errorf("%w: %s", ErrAppConflict, app.ID)
		}
		return false, nil
	}
	if app.Icon != "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO custom_app_icons(app_id,icon) VALUES(?,?)`, app.ID, app.Icon)
	}
	return true, err
}
