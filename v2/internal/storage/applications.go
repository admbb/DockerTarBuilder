package storage

import (
	"context"
	"errors"
	"netflow-plus-v2/internal/catalog"
	"regexp"
	"strings"
)

var appIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (s *Store) ensureCustomApps(ctx context.Context) error {
	// The icon table also works with databases created before icon selection.
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS custom_apps(id TEXT PRIMARY KEY,name TEXT NOT NULL,category TEXT NOT NULL) WITHOUT ROWID;
		CREATE TABLE IF NOT EXISTS custom_app_icons(app_id TEXT PRIMARY KEY,icon TEXT NOT NULL) WITHOUT ROWID`)
	return err
}

func (s *Store) CustomApps(ctx context.Context) ([]catalog.App, error) {
	if err := s.ensureCustomApps(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.name,a.category,COALESCE(i.icon,'') FROM custom_apps a LEFT JOIN custom_app_icons i ON i.app_id=a.id ORDER BY a.name,a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []catalog.App{}
	for rows.Next() {
		var a catalog.App
		if err := rows.Scan(&a.ID, &a.Name, &a.Category, &a.Icon); err != nil {
			return nil, err
		}
		if !catalog.ValidIcon(a.Icon) {
			a.Icon = ""
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func normalizedCustomApp(a catalog.App) (catalog.App, error) {
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	a.Category = strings.TrimSpace(a.Category)
	if !appIDPattern.MatchString(a.ID) || a.Name == "" || len(a.Name) > 120 || a.Category == "" || len(a.Category) > 80 || !catalog.ValidIcon(a.Icon) {
		return a, errors.New("invalid app")
	}
	return a, nil
}

func (s *Store) SaveCustomApp(ctx context.Context, a catalog.App) error {
	_, err := s.importRuleBackup(ctx, []catalog.App{a}, nil, nil, false)
	return err
}
