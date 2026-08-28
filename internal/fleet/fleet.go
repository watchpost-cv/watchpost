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
type PeerStatus struct {
	ID        string     `json:"id"`
	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Pending   int        `json:"pending"`
	Delivered int        `json:"delivered"`
	Received  int        `json:"received"`
}

func (s *Service) List(ctx context.Context) ([]PeerStatus, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT p.id,p.state,p.created_at,p.revoked_at,COALESCE(SUM(CASE WHEN o.id IS NOT NULL AND o.delivered_at IS NULL THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN o.delivered_at IS NOT NULL THEN 1 ELSE 0 END),0),(SELECT COUNT(*) FROM federation_inbox i WHERE i.peer_id=p.id) FROM peers p LEFT JOIN federation_outbox o ON o.peer_id=p.id GROUP BY p.id,p.state,p.created_at,p.revoked_at ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []PeerStatus{}
	for rows.Next() {
		var v PeerStatus
		var created string
		var revoked *string
		if err = rows.Scan(&v.ID, &v.State, &created, &revoked, &v.Pending, &v.Delivered, &v.Received); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if revoked != nil {
			x, _ := time.Parse(time.RFC3339Nano, *revoked)
			v.RevokedAt = &x
		}
		items = append(items, v)
	}
	return items, rows.Err()
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
	result, err := s.s.DB.ExecContext(ctx, `UPDATE peers SET state='revoked',revoked_at=? WHERE id=? AND state='active'`, s.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("active peer not found")
	}
	return nil
}
func signingBytes(e Envelope) []byte {
	copy := e
	copy.Signature = ""
	bytes, _ := json.Marshal(copy)
	return bytes
}
