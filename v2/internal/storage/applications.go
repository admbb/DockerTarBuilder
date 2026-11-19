package storage

import (
	"context"
	"errors"
	"netflow-plus-v2/internal/catalog"
	"regexp"
	"strings"
)

var appIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (s *Store) CustomApps(ctx context.Context) ([]catalog.App, error) {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS custom_apps(id TEXT PRIMARY KEY,name TEXT NOT NULL,category TEXT NOT NULL) WITHOUT ROWID`); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,category FROM custom_apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []catalog.App{}
	for rows.Next() {
		var a catalog.App
		if err := rows.Scan(&a.ID, &a.Name, &a.Category); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}
func (s *Store) SaveCustomApp(ctx context.Context, a catalog.App) error {
	if _, err := s.CustomApps(ctx); err != nil {
		return err
	}
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	a.Category = strings.TrimSpace(a.Category)
	if !appIDPattern.MatchString(a.ID) || a.Name == "" || len(a.Name) > 120 || a.Category == "" || len(a.Category) > 80 || a.Icon != "" {
		return errors.New("invalid app")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO custom_apps(id,name,category) VALUES(?,?,?)`, a.ID, a.Name, a.Category)
	return err
}
