package posts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/store"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var kinds = map[string]bool{"host": true, "http_endpoint": true, "tcp_service": true, "tls_certificate": true, "network_device": true, "ups": true, "environmental_sensor": true, "storage_appliance": true}

type Post struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Address     string            `json:"address"`
	Owner       string            `json:"owner"`
	Labels      map[string]string `json:"labels"`
	Maintenance bool              `json:"maintenance"`
	Archived    bool              `json:"archived"`
	Version     int               `json:"version"`
}
type Store struct{ s *store.Store }

func New(s *store.Store) *Store { return &Store{s: s} }
func (s *Store) Create(ctx context.Context, p Post, entry audit.Entry) (Post, error) {
	if !valid(p) {
		return Post{}, errors.New("invalid post")
	}
	for k, v := range p.Labels {
		if len(k) > 63 || len(v) > 255 {
			return Post{}, errors.New("invalid labels")
		}
	}
	labels, _ := json.Marshal(p.Labels)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Post{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO posts(id,name,kind,address,owner,labels_json,maintenance,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Kind, p.Address, p.Owner, string(labels), p.Maintenance, now, now); err != nil {
		return Post{}, err
	}
	entry.ObjectType = "post"
	entry.ObjectID = p.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Post{}, err
	}
	if err = tx.Commit(); err != nil {
		return Post{}, err
	}
	return s.Get(ctx, p.ID)
}
func (s *Store) Get(ctx context.Context, id string) (Post, error) {
	var p Post
	var labels string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,name,kind,address,owner,labels_json,maintenance,archived,version FROM posts WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Kind, &p.Address, &p.Owner, &labels, &p.Maintenance, &p.Archived, &p.Version)
	if err != nil {
		return Post{}, err
	}
	if err = json.Unmarshal([]byte(labels), &p.Labels); err != nil {
		return Post{}, err
	}
	return p, nil
}
// List returns a bounded page of posts ordered by name,id.
func (s *Store) List(ctx context.Context, limit, offset int) ([]Post, error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,name,kind,address,owner,labels_json,maintenance,archived,version FROM posts ORDER BY name,id LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Post{}
	for rows.Next() {
		var p Post
		var labels string
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Address, &p.Owner, &labels, &p.Maintenance, &p.Archived, &p.Version); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(labels), &p.Labels); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// Count returns the total number of posts for pagination.
func (s *Store) Count(ctx context.Context) (int, error) {
	var count int
	if err := s.s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM posts`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
func (s *Store) Update(ctx context.Context, p Post, expected int, entry audit.Entry) (Post, error) {
	if !valid(p) {
		return Post{}, errors.New("invalid post")
	}
	labels, _ := json.Marshal(p.Labels)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Post{}, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE posts SET name=?,address=?,owner=?,labels_json=?,maintenance=?,archived=?,version=version+1,updated_at=? WHERE id=? AND version=?`, p.Name, p.Address, p.Owner, string(labels), p.Maintenance, p.Archived, time.Now().UTC().Format(time.RFC3339Nano), p.ID, expected)
	if err != nil {
		return Post{}, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return Post{}, errors.New("post version conflict")
	}
	entry.ObjectType = "post"
	entry.ObjectID = p.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Post{}, err
	}
	if err = tx.Commit(); err != nil {
		return Post{}, err
	}
	return s.Get(ctx, p.ID)
}

func valid(p Post) bool {
	if !idPattern.MatchString(p.ID) || len(p.Name) < 1 || len(p.Name) > 120 || len(p.Address) > 255 || !kinds[p.Kind] || len(p.Labels) > 32 {
		return false
	}
	for k, v := range p.Labels {
		if len(k) > 63 || len(v) > 255 {
			return false
		}
	}
	return true
}

// Delete permanently removes a post and all evidence and credentials scoped to it.
func (s *Store) Delete(ctx context.Context, id string, entry audit.Entry) error {
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM posts WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return sql.ErrNoRows
	}
	statements := []string{
		`DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE post_id=?)`, `DELETE FROM conversations WHERE post_id=?`, `DELETE FROM action_requests WHERE post_id=?`,
		`DELETE FROM device_profile_oids WHERE profile_id IN (SELECT id FROM device_profiles WHERE post_id=?)`, `DELETE FROM device_profiles WHERE post_id=?`,
		`DELETE FROM notification_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE post_id=?)`, `DELETE FROM incident_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE post_id=?)`,
		`DELETE FROM alerts WHERE post_id=?`, `DELETE FROM rules WHERE post_id=?`, `DELETE FROM observations WHERE post_id=?`, `DELETE FROM collector_pairing_tokens WHERE post_id=?`,
		`DELETE FROM collector_keys WHERE post_id=?`, `DELETE FROM logs WHERE post_id=?`, `DELETE FROM changes WHERE post_id=?`, `DELETE FROM post_dependencies WHERE post_id=? OR depends_on_id=?`,
	}
	for _, statement := range statements {
		args := []any{id}
		if strings.Contains(statement, " OR depends_on_id") {
			args = append(args, id)
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM posts WHERE id=?`, id); err != nil {
		return err
	}
	entry.ObjectType = "post"
	entry.ObjectID = id
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) AddDependency(ctx context.Context, id, depends string, entry audit.Entry) error {
	if id == depends {
		return errors.New("self dependency")
	}
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cycle int
	err = tx.QueryRowContext(ctx, `WITH RECURSIVE reach(id) AS (SELECT depends_on_id FROM post_dependencies WHERE post_id=? UNION SELECT d.depends_on_id FROM post_dependencies d JOIN reach r ON d.post_id=r.id) SELECT COUNT(*) FROM reach WHERE id=?`, depends, id).Scan(&cycle)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if cycle > 0 {
		return errors.New("dependency cycle")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO post_dependencies(post_id,depends_on_id) VALUES(?,?)`, id, depends); err != nil {
		return err
	}
	entry.ObjectType = "post"
	entry.ObjectID = id
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
