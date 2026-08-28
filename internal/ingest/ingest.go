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

func (s *Service) AcceptBatch(ctx context.Context, secret string, observations []Observation, sentAt time.Time) error {
	if len(observations) < 1 || len(observations) > 128 {
		return errors.New("invalid observation batch")
	}
	now := s.now().UTC()
	h := sha256.Sum256([]byte(secret))
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var post string
	var last int64
	var revoked sql.NullString
	first := observations[0]
	if err = tx.QueryRowContext(ctx, `SELECT post_id,last_sequence,revoked_at FROM collector_keys WHERE id=? AND secret_hash=?`, first.CollectorID, h[:]).Scan(&post, &last, &revoked); err != nil || revoked.Valid || post != first.PostID {
		return errors.New("collector authentication failed")
	}
	for index, o := range observations {
		if o.Version != 1 || o.PostID != post || o.CollectorID != first.CollectorID || o.Sequence != last+int64(index)+1 || len(o.Signal) < 1 || len(o.Signal) > 128 || len(o.Labels) > 32 || !quality[o.Quality] || (o.Value != nil && (math.IsNaN(*o.Value) || math.IsInf(*o.Value, 0))) || o.ObservedAt.Before(now.Add(-24*time.Hour)) || o.ObservedAt.After(now.Add(5*time.Minute)) {
			return errors.New("invalid or non-contiguous observation batch")
		}
		labels, _ := json.Marshal(o.Labels)
		if _, err = tx.ExecContext(ctx, `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, o.PostID, o.CollectorID, o.ObservedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), o.Sequence, o.Signal, o.Value, o.Unit, o.Quality, string(labels)); err != nil {
			return err
		}
	}
	latest := observations[0].ObservedAt
	partial := false
	for _, observation := range observations {
		if observation.ObservedAt.After(latest) {
			latest = observation.ObservedAt
		}
		if observation.Quality != "good" || observation.Signal == "collector.dropped_samples" {
			partial = true
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE collector_keys SET last_sequence=?,last_seen_at=?,last_observed_at=?,last_sent_at=?,last_error='',partial=? WHERE id=?`, observations[len(observations)-1].Sequence, now.Format(time.RFC3339Nano), latest.UTC().Format(time.RFC3339Nano), sentAt.UTC().Format(time.RFC3339Nano), partial, first.CollectorID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) RecordRejection(ctx context.Context, collectorID string, cause error) {
	message := cause.Error()
	if len(message) > 240 {
		message = message[:240]
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, _ = s.s.DB.ExecContext(ctx, `UPDATE collector_keys SET last_error=?,last_rejected_at=?,rejected_count=rejected_count+1 WHERE id=?`, message, now, collectorID)
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
