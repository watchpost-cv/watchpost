package posts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var kinds = map[string]bool{"host": true, "http_endpoint": true, "tcp_service": true, "tls_certificate": true, "network_device": true, "ups": true, "environmental_sensor": true, "storage_appliance": true}

type Post struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Owner       string            `json:"owner"`
	Labels      map[string]string `json:"labels"`
	Maintenance bool              `json:"maintenance"`
	Archived    bool              `json:"archived"`
	Version     int               `json:"version"`
}
type Store struct{ s *store.Store }

func New(s *store.Store) *Store { return &Store{s: s} }
func (s *Store) Create(ctx context.Context, p Post) (Post, error) {
	if !idPattern.MatchString(p.ID) || len(p.Name) < 1 || len(p.Name) > 120 || !kinds[p.Kind] || len(p.Labels) > 32 {
		return Post{}, errors.New("invalid post")
	}
	for k, v := range p.Labels {
		if len(k) > 63 || len(v) > 255 {
			return Post{}, errors.New("invalid labels")
		}
	}
	labels, _ := json.Marshal(p.Labels)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.s.DB.ExecContext(ctx, `INSERT INTO posts(id,name,kind,owner,labels_json,maintenance,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Kind, p.Owner, string(labels), p.Maintenance, now, now)
	if err != nil {
		return Post{}, err
	}
	return s.Get(ctx, p.ID)
}
func (s *Store) Get(ctx context.Context, id string) (Post, error) {
	var p Post
	var labels string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,name,kind,owner,labels_json,maintenance,archived,version FROM posts WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Kind, &p.Owner, &labels, &p.Maintenance, &p.Archived, &p.Version)
	if err != nil {
		return Post{}, err
	}
	if err = json.Unmarshal([]byte(labels), &p.Labels); err != nil {
		return Post{}, err
	}
	return p, nil
}
func (s *Store) List(ctx context.Context) ([]Post, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,name,kind,owner,labels_json,maintenance,archived,version FROM posts ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Post{}
	for rows.Next() {
		var p Post
		var labels string
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Owner, &labels, &p.Maintenance, &p.Archived, &p.Version); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(labels), &p.Labels); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (s *Store) Update(ctx context.Context, p Post, expected int) (Post, error) {
	labels, _ := json.Marshal(p.Labels)
	r, err := s.s.DB.ExecContext(ctx, `UPDATE posts SET name=?,owner=?,labels_json=?,maintenance=?,archived=?,version=version+1,updated_at=? WHERE id=? AND version=?`, p.Name, p.Owner, string(labels), p.Maintenance, p.Archived, time.Now().UTC().Format(time.RFC3339Nano), p.ID, expected)
	if err != nil {
		return Post{}, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return Post{}, errors.New("post version conflict")
	}
	return s.Get(ctx, p.ID)
}
func (s *Store) AddDependency(ctx context.Context, id, depends string) error {
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
	return tx.Commit()
}
