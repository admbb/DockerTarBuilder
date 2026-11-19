package storage

import "context"

func (s *Store) ensureAppIconOverrides(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_icon_overrides(app_id TEXT PRIMARY KEY,icon TEXT NOT NULL,svg TEXT NOT NULL) WITHOUT ROWID`)
	return err
}

type AppIconOverride struct {
	Path string
	SVG  string
}

func (s *Store) AppIconOverrides(ctx context.Context) (map[string]AppIconOverride, error) {
	if err := s.ensureAppIconOverrides(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT app_id,icon,svg FROM app_icon_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	icons := make(map[string]AppIconOverride)
	for rows.Next() {
		var id string
		var icon AppIconOverride
		if err := rows.Scan(&id, &icon.Path, &icon.SVG); err != nil {
			return nil, err
		}
		icons[id] = icon
	}
	return icons, rows.Err()
}

func (s *Store) SaveAppIconOverride(ctx context.Context, id string, icon *AppIconOverride) error {
	if err := s.ensureAppIconOverrides(ctx); err != nil {
		return err
	}
	if icon == nil {
		_, err := s.db.ExecContext(ctx, `DELETE FROM app_icon_overrides WHERE app_id=?`, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO app_icon_overrides(app_id,icon,svg) VALUES(?,?,?)
		ON CONFLICT(app_id) DO UPDATE SET icon=excluded.icon,svg=excluded.svg`, id, icon.Path, icon.SVG)
	return err
}
