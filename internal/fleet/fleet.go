package fleet

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/store"
	"time"
)

type Envelope struct {
	EventID   string          `json:"event_id"`
	Kind      string          `json:"kind"`
	CreatedAt time.Time       `json:"created_at"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}
type Service struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Service { return &Service{s: s, now: time.Now} }
func (s *Service) Enroll(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errors.New("peer ID required")
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(bytes)
	hash := sha256.Sum256([]byte(secret))
	_, err := s.s.DB.ExecContext(ctx, `INSERT INTO peers(id,secret_hash,state,created_at) VALUES(?,?,'active',?)`, id, hash[:], s.now().UTC().Format(time.RFC3339Nano))
	return secret, err
}
func Sign(secret string, envelope Envelope) Envelope {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signingBytes(envelope))
	envelope.Signature = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return envelope
}
func (s *Service) Receive(ctx context.Context, peerID, secret string, envelope Envelope) error {
	var expected []byte
	var state string
	if err := s.s.DB.QueryRowContext(ctx, `SELECT secret_hash,state FROM peers WHERE id=?`, peerID).Scan(&expected, &state); err != nil || state != "active" {
		return errors.New("peer unavailable")
	}
	actual := sha256.Sum256([]byte(secret))
	if !hmac.Equal(expected, actual[:]) {
		return errors.New("peer authentication failed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return errors.New("invalid signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signingBytes(envelope))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.New("invalid signature")
	}
	if envelope.EventID == "" || envelope.CreatedAt.Before(s.now().Add(-24*time.Hour)) || envelope.CreatedAt.After(s.now().Add(5*time.Minute)) || len(envelope.Payload) > 256<<10 {
		return errors.New("invalid envelope")
	}
	payloadHash := sha256.Sum256(envelope.Payload)
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO federation_inbox(peer_id,event_id,received_at,payload_hash) VALUES(?,?,?,?)`, peerID, envelope.EventID, s.now().UTC().Format(time.RFC3339Nano), payloadHash[:])
	if err != nil {
		return errors.New("duplicate or invalid event")
	}
	return nil
}
func (s *Service) Queue(ctx context.Context, peerID, eventID, kind string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > 256<<10 {
		return errors.New("invalid payload")
	}
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO federation_outbox(peer_id,event_id,kind,payload_json,created_at) VALUES(?,?,?,?,?)`, peerID, eventID, kind, string(encoded), s.now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Service) Revoke(ctx context.Context, id string) error {
	_, err := s.s.DB.ExecContext(ctx, `UPDATE peers SET state='revoked',revoked_at=? WHERE id=?`, s.now().UTC().Format(time.RFC3339Nano), id)
	return err
}
func signingBytes(e Envelope) []byte {
	copy := e
	copy.Signature = ""
	bytes, _ := json.Marshal(copy)
	return bytes
}
