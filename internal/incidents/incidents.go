package incidents

import (
	"context"
	"errors"
	"fmt"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
	"time"
)

type Incident struct {
	ID                   int64  `json:"id"`
	Title                string `json:"title"`
	Severity             string `json:"severity"`
	Status               string `json:"status"`
	Owner                string `json:"owner"`
	Summary              string `json:"summary"`
	CreatedAt, UpdatedAt time.Time
	ResolvedAt           *time.Time
}
type Entry struct {
	ID, IncidentID    int64
	At                time.Time
	Kind, Actor, Body string
}
type Store struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Store { return &Store{s: s, now: time.Now} }
func (s *Store) Create(ctx context.Context, title, severity, actor string, alertIDs []int64, entry audit.Entry) (Incident, error) {
	if title == "" || !map[string]bool{"info": true, "warning": true, "critical": true}[severity] {
		return Incident{}, errors.New("invalid incident")
	}
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO incidents(title,severity,status,created_at,updated_at) VALUES(?,?,'open',?,?)`, title, severity, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Incident{}, err
	}
	id, _ := result.LastInsertId()
	for _, alert := range alertIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO incident_alerts(incident_id,alert_id) VALUES(?,?)`, id, alert); err != nil {
			return Incident{}, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,at,kind,actor,body) VALUES(?,?,'created',?,?)`, id, now.Format(time.RFC3339Nano), actor, title); err != nil {
		return Incident{}, err
	}
	entry.ObjectType = "incident"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Incident{}, err
	}
	if err = tx.Commit(); err != nil {
		return Incident{}, err
	}
	return Incident{ID: id, Title: title, Severity: severity, Status: "open", CreatedAt: now, UpdatedAt: now}, nil
}
func (s *Store) Transition(ctx context.Context, id int64, status, actor, summary string, entry audit.Entry) (Incident, error) {
	if !map[string]bool{"open": true, "investigating": true, "mitigated": true, "resolved": true}[status] {
		return Incident{}, errors.New("invalid status")
	}
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET status=?,summary=?,updated_at=?,resolved_at=? WHERE id=?`, status, summary, now.Format(time.RFC3339Nano), nullable(status == "resolved", now), id)
	if err != nil {
		return Incident{}, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return Incident{}, errors.New("incident not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,at,kind,actor,body) VALUES(?,?,?,?,?)`, id, now.Format(time.RFC3339Nano), "status", actor, status+": "+summary); err != nil {
		return Incident{}, err
	}
	entry.ObjectType = "incident"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Incident{}, err
	}
	if err = tx.Commit(); err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}
func (s *Store) AddNote(ctx context.Context, id int64, actor, body string, entry audit.Entry) error {
	if body == "" || len(body) > 10000 {
		return errors.New("invalid note")
	}
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,at,kind,actor,body) VALUES(?,?,'note',?,?)`, id, s.now().UTC().Format(time.RFC3339Nano), actor, body); err != nil {
		return err
	}
	entry.ObjectType = "incident"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Assign(ctx context.Context, id int64, owner, actor string, entry audit.Entry) (Incident, error) {
	if owner == "" || len(owner) > 254 {
		return Incident{}, errors.New("invalid owner")
	}
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Incident{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET owner=?,updated_at=? WHERE id=?`, owner, now.Format(time.RFC3339Nano), id)
	if err != nil {
		return Incident{}, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return Incident{}, errors.New("incident not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,at,kind,actor,body) VALUES(?,?,'assignment',?,?)`, id, now.Format(time.RFC3339Nano), actor, owner); err != nil {
		return Incident{}, err
	}
	entry.ObjectType = "incident"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Incident{}, err
	}
	if err = tx.Commit(); err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}
func (s *Store) Get(ctx context.Context, id int64) (Incident, error) {
	var i Incident
	var created, updated string
	var resolved *string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,title,severity,status,owner,summary,created_at,updated_at,resolved_at FROM incidents WHERE id=?`, id).Scan(&i.ID, &i.Title, &i.Severity, &i.Status, &i.Owner, &i.Summary, &created, &updated, &resolved)
	if err != nil {
		return Incident{}, err
	}
	i.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	i.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if resolved != nil {
		v, _ := time.Parse(time.RFC3339Nano, *resolved)
		i.ResolvedAt = &v
	}
	return i, nil
}
func (s *Store) List(ctx context.Context, limit int) ([]Incident, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid limit")
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,title,severity,status,owner,summary,created_at,updated_at,resolved_at FROM incidents ORDER BY updated_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Incident{}
	for rows.Next() {
		var i Incident
		var created, updated string
		var resolved *string
		if err = rows.Scan(&i.ID, &i.Title, &i.Severity, &i.Status, &i.Owner, &i.Summary, &created, &updated, &resolved); err != nil {
			return nil, err
		}
		i.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		i.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if resolved != nil {
			v, _ := time.Parse(time.RFC3339Nano, *resolved)
			i.ResolvedAt = &v
		}
		items = append(items, i)
	}
	return items, rows.Err()
}
func (s *Store) Timeline(ctx context.Context, id int64, limit int) ([]Entry, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid limit")
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,incident_id,at,kind,actor,body FROM incident_timeline WHERE incident_id=? ORDER BY at,id LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []Entry{}
	for rows.Next() {
		var e Entry
		var at string
		if err = rows.Scan(&e.ID, &e.IncidentID, &at, &e.Kind, &e.Actor, &e.Body); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
func nullable(ok bool, t time.Time) any {
	if ok {
		return t.Format(time.RFC3339Nano)
	}
	return nil
}
