package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

type Service struct {
	s   *store.Store
	now func() time.Time
}
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Enrollment struct {
	Version     int    `json:"version"`
	PostID      string `json:"post_id"`
	CollectorID string `json:"collector_id"`
	Secret      string `json:"secret"`
}

func New(s *store.Store) *Service { return &Service{s: s, now: time.Now} }

func (s *Service) Create(ctx context.Context, postID string, lifetime time.Duration) (Token, error) {
	if lifetime < time.Minute || lifetime > 30*time.Minute {
		return Token{}, errors.New("invalid pairing lifetime")
	}
	raw, err := randomSecret(32)
	if err != nil {
		return Token{}, err
	}
	hash := sha256.Sum256([]byte(raw))
	expires := s.now().UTC().Add(lifetime)
	result, err := s.s.DB.ExecContext(ctx, `INSERT INTO collector_pairing_tokens(token_hash,post_id,expires_at) SELECT ?,id,? FROM posts WHERE id=? AND archived=0`, hash[:], expires.Format(time.RFC3339Nano), postID)
	if err != nil {
		return Token{}, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Token{}, errors.New("post unavailable for pairing")
	}
	return Token{Token: raw, ExpiresAt: expires}, nil
}

func (s *Service) Consume(ctx context.Context, token, collectorID string) (Enrollment, error) {
	if token == "" || collectorID == "" {
		return Enrollment{}, errors.New("invalid pairing request")
	}
	tokenHash := sha256.Sum256([]byte(token))
	secret, err := randomSecret(32)
	if err != nil {
		return Enrollment{}, err
	}
	secretHash := sha256.Sum256([]byte(secret))
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, err
	}
	defer tx.Rollback()
	var postID, expires string
	var used any
	if err = tx.QueryRowContext(ctx, `SELECT post_id,expires_at,used_at FROM collector_pairing_tokens WHERE token_hash=?`, tokenHash[:]).Scan(&postID, &expires, &used); err != nil {
		return Enrollment{}, errors.New("pairing token invalid")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if used != nil || !now.Before(expiresAt) {
		return Enrollment{}, errors.New("pairing token expired or used")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO collector_keys(id,post_id,secret_hash) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET secret_hash=excluded.secret_hash,revoked_at=NULL,last_sequence=0,last_seen_at=NULL,last_observed_at=NULL,last_sent_at=NULL,last_error='',last_rejected_at=NULL,rejected_count=0,partial=0 WHERE collector_keys.post_id=excluded.post_id`, collectorID, postID, secretHash[:])
	if err != nil {
		return Enrollment{}, errors.New("collector identity unavailable")
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Enrollment{}, errors.New("collector identity belongs to another post")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE collector_pairing_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL`, now.Format(time.RFC3339Nano), tokenHash[:]); err != nil {
		return Enrollment{}, err
	}
	if err = tx.Commit(); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Version: 1, PostID: postID, CollectorID: collectorID, Secret: secret}, nil
}

func randomSecret(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
