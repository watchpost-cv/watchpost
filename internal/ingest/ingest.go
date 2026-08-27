package ingest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/store"
	"math"
	"time"
)

type Observation struct {
	Version     int               `json:"version"`
	PostID      string            `json:"post_id"`
	CollectorID string            `json:"collector_id"`
	ObservedAt  time.Time         `json:"observed_at"`
	Sequence    int64             `json:"sequence"`
	Signal      string            `json:"signal"`
	Value       *float64          `json:"value"`
	Unit        string            `json:"unit"`
	Quality     string            `json:"quality"`
	Labels      map[string]string `json:"labels"`
}
type Service struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Service { return &Service{s: s, now: time.Now} }
func (s *Service) Enroll(ctx context.Context, id, postID string) (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	secret := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(secret))
	_, e := s.s.DB.ExecContext(ctx, `INSERT INTO collector_keys(id,post_id,secret_hash) VALUES(?,?,?)`, id, postID, h[:])
	return secret, e
}
func (s *Service) Accept(ctx context.Context, secret string, o Observation) error {
	if o.Version != 1 || o.Sequence < 1 || len(o.Signal) < 1 || len(o.Signal) > 128 || len(o.Labels) > 32 || !quality[o.Quality] || (o.Value != nil && (math.IsNaN(*o.Value) || math.IsInf(*o.Value, 0))) {
		return errors.New("invalid observation")
	}
	now := s.now().UTC()
	if o.ObservedAt.Before(now.Add(-24*time.Hour)) || o.ObservedAt.After(now.Add(5*time.Minute)) {
		return errors.New("observation outside clock bounds")
	}
	labels, _ := json.Marshal(o.Labels)
	h := sha256.Sum256([]byte(secret))
	tx, e := s.s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var post string
	var last int64
	var revoked sql.NullString
	e = tx.QueryRowContext(ctx, `SELECT post_id,last_sequence,revoked_at FROM collector_keys WHERE id=? AND secret_hash=?`, o.CollectorID, h[:]).Scan(&post, &last, &revoked)
	if e != nil || revoked.Valid || post != o.PostID {
		return errors.New("collector authentication failed")
	}
	if o.Sequence <= last {
		return errors.New("replayed observation")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, o.PostID, o.CollectorID, o.ObservedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), o.Sequence, o.Signal, o.Value, o.Unit, o.Quality, string(labels))
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE collector_keys SET last_sequence=? WHERE id=?`, o.Sequence, o.CollectorID)
	if e != nil {
		return e
	}
	return tx.Commit()
}

var quality = map[string]bool{"good": true, "uncertain": true, "bad": true, "missing": true, "stale": true}
