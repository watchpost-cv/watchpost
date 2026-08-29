package ingest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/store"
	"math"
	"sync"
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
	first := observations[0]
	info, err := s.lookupKey(ctx, tx, first.CollectorID, h[:], now)
	if err != nil || info.revoked || info.post != first.PostID || (!info.active && !info.pending) {
		return errors.New("collector authentication failed")
	}
	if info.pending {
		if err = s.promotePending(ctx, tx, first.CollectorID); err != nil {
			return err
		}
	}
	if !s.allow(first.CollectorID, len(observations), now) {
		return errors.New("collector ingestion rate exceeded")
	}
	for index, o := range observations {
		if o.Version != 1 || o.PostID != info.post || o.CollectorID != first.CollectorID || o.Sequence != info.last+int64(index)+1 || len(o.Signal) < 1 || len(o.Signal) > 128 || len(o.Labels) > 32 || !quality[o.Quality] || (o.Value != nil && (math.IsNaN(*o.Value) || math.IsInf(*o.Value, 0))) || o.ObservedAt.Before(now.Add(-24*time.Hour)) || o.ObservedAt.After(now.Add(5*time.Minute)) {
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
	s     *store.Store
	now   func() time.Time
	mu    sync.Mutex
	rate  map[string]*rateWindow
	limit int
}

type rateWindow struct {
	minuteStart time.Time
	samples     int
}

func New(s *store.Store) *Service { return &Service{s: s, now: time.Now, rate: map[string]*rateWindow{}, limit: 3600} }

// SetIngestRate bounds accepted samples per collector per minute. Zero or a
// negative value disables the budget.
func (s *Service) SetIngestRate(limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limit = limit
}

func (s *Service) allow(collectorID string, samples int, now time.Time) bool {
	if s.limit <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	window, ok := s.rate[collectorID]
	if !ok || now.Sub(window.minuteStart) >= time.Minute {
		window = &rateWindow{minuteStart: now}
		s.rate[collectorID] = window
	}
	if window.samples+samples > s.limit {
		return false
	}
	window.samples += samples
	return true
}
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

// Authenticate verifies a collector credential without ingesting anything. It
// lets handlers reject unknown identities before exposing storage state or
// consuming work. A pending (unconfirmed rotation) credential is accepted but
// not promoted here.
func (s *Service) Authenticate(ctx context.Context, collectorID, secret string) error {
	if collectorID == "" || secret == "" {
		return errors.New("collector authentication failed")
	}
	h := sha256.Sum256([]byte(secret))
	info, err := s.lookupKey(ctx, s.s.DB, collectorID, h[:], s.now().UTC())
	if err != nil || info.revoked || (!info.active && !info.pending) {
		return errors.New("collector authentication failed")
	}
	return nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type keyInfo struct {
	post    string
	last    int64
	revoked bool
	active  bool
	pending bool
}

// lookupKey resolves a presented credential against a collector key, allowing
// either the active credential or an unexpired pending replacement during an
// overlap-and-confirm rotation.
func (s *Service) lookupKey(ctx context.Context, q queryer, id string, presented []byte, now time.Time) (keyInfo, error) {
	var info keyInfo
	var revoked, pendingExpires sql.NullString
	var activeHash, pendingHash []byte
	err := q.QueryRowContext(ctx, `SELECT post_id,last_sequence,revoked_at,secret_hash,pending_secret_hash,pending_expires_at FROM collector_keys WHERE id=?`, id).Scan(&info.post, &info.last, &revoked, &activeHash, &pendingHash, &pendingExpires)
	if err != nil {
		return info, err
	}
	info.revoked = revoked.Valid
	info.active = hmac.Equal(activeHash, presented)
	if len(pendingHash) == sha256.Size {
		expired := false
		if pendingExpires.Valid {
			expiresAt, err := time.Parse(time.RFC3339Nano, pendingExpires.String)
			if err != nil || !now.Before(expiresAt) {
				expired = true
			}
		}
		info.pending = !expired && hmac.Equal(pendingHash, presented)
	}
	return info, nil
}

// promotePending makes an unconfirmed replacement credential active. It is
// called only inside an accepted write transaction after a batch was
// authenticated with the pending credential.
func (s *Service) promotePending(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, `UPDATE collector_keys SET secret_hash=pending_secret_hash,pending_secret_hash=NULL,pending_expires_at=NULL,last_error='' WHERE id=? AND pending_secret_hash IS NOT NULL`, id)
	return err
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
	info, e := s.lookupKey(ctx, tx, o.CollectorID, h[:], now)
	if e != nil || info.revoked || info.post != o.PostID || (!info.active && !info.pending) {
		return errors.New("collector authentication failed")
	}
	if info.pending {
		if e = s.promotePending(ctx, tx, o.CollectorID); e != nil {
			return e
		}
	}
	if !s.allow(o.CollectorID, 1, now) {
		return errors.New("collector ingestion rate exceeded")
	}
	if o.Sequence <= info.last {
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
