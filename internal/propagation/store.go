package propagation

import (
	"context"
	"database/sql"
	"encoding/json"
	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/watchpost-cv/watchpost/internal/store"
	"time"
)

type StateStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewStateStore(st *store.Store) *StateStore { return &StateStore{db: st.DB, now: time.Now} }
func (s *StateStore) SaveProfile(ctx context.Context, p core.Profile) error {
	selector, _ := json.Marshal(p.Selector)
	kinds, _ := json.Marshal(p.Kinds)
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO propagation_profiles(id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,selector_json=excluded.selector_json,kinds_json=excluded.kinds_json,mode=excluded.mode,schedule=excluded.schedule,maintenance_window=excluded.maintenance_window,enabled=excluded.enabled,updated_at=excluded.updated_at`, p.ID, p.Name, string(selector), string(kinds), string(p.Mode), p.Schedule, p.MaintenanceWindow, boolInt(p.Enabled), now, now)
	return err
}
func (s *StateStore) DeleteProfile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM propagation_profiles WHERE id=?`, id)
	return err
}
func (s *StateStore) ListProfiles(ctx context.Context) ([]core.Profile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,selector_json,kinds_json,mode,schedule,maintenance_window,enabled FROM propagation_profiles ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.Profile{}
	for rows.Next() {
		var p core.Profile
		var sel, kinds, mode string
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &sel, &kinds, &mode, &p.Schedule, &p.MaintenanceWindow, &enabled); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sel), &p.Selector)
		_ = json.Unmarshal([]byte(kinds), &p.Kinds)
		p.Mode = core.ReconcileMode(mode)
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *StateStore) RecordHistory(ctx context.Context, h core.HistoryRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO propagation_history(id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, h.ID, h.PlanID, h.Actor, h.Target, h.Status, h.Applied, h.Failed, h.RolledBack, h.Detail, h.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *StateStore) ListHistory(ctx context.Context, limit int) ([]core.HistoryRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,plan_id,actor,target,status,applied,failed,rolled_back,detail,created_at FROM propagation_history ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.HistoryRecord{}
	for rows.Next() {
		var h core.HistoryRecord
		var at string
		if err := rows.Scan(&h.ID, &h.PlanID, &h.Actor, &h.Target, &h.Status, &h.Applied, &h.Failed, &h.RolledBack, &h.Detail, &at); err != nil {
			return nil, err
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, h)
	}
	return out, rows.Err()
}
