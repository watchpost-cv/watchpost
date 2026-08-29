package agentpairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

const Lifetime = 10 * time.Minute

type Service struct {
	s   *store.Store
	now func() time.Time
}

type Request struct {
	ID             string    `json:"id"`
	InstallationID string    `json:"installation_id"`
	Hostname       string    `json:"hostname"`
	Platform       string    `json:"platform"`
	AgentVersion   string    `json:"agent_version"`
	Phrase         string    `json:"phrase"`
	State          string    `json:"state"`
	PostID         string    `json:"post_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

type Enrollment struct {
	State       string `json:"state"`
	PostID      string `json:"post_id,omitempty"`
	CollectorID string `json:"collector_id,omitempty"`
	Credential  string `json:"credential,omitempty"`
}

type Connection struct {
	InstallationID string     `json:"installation_id"`
	PostID         string     `json:"post_id"`
	Hostname       string     `json:"hostname"`
	Platform       string     `json:"platform"`
	AgentVersion   string     `json:"agent_version"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	Status         string     `json:"status"`
}

func New(s *store.Store) *Service { return &Service{s: s, now: time.Now} }

func (s *Service) Create(ctx context.Context, installationID, secret, hostname, platform, version string) (Request, error) {
	if installationID == "" || len(secret) < 32 || hostname == "" || platform == "" {
		return Request{}, errors.New("invalid pairing request")
	}
	var pending int
	if err := s.s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_pairing_requests WHERE state='pending' AND expires_at>?`, s.now().UTC().Format(time.RFC3339Nano)).Scan(&pending); err != nil {
		return Request{}, err
	}
	if pending >= 100 {
		return Request{}, errors.New("too many pending pairing requests")
	}
	id, err := random(16)
	if err != nil {
		return Request{}, err
	}
	phrase, err := pairingPhrase()
	if err != nil {
		return Request{}, err
	}
	now := s.now().UTC()
	expires := now.Add(Lifetime)
	hash := sha256.Sum256([]byte(secret))
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO agent_pairing_requests(id,request_secret_hash,installation_id,hostname,platform,agent_version,phrase,state,expires_at,created_at) VALUES(?,?,?,?,?,?,?,'pending',?,?)`, id, hash[:], installationID, hostname, platform, version, phrase, expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Request{}, err
	}
	return Request{ID: id, InstallationID: installationID, Hostname: hostname, Platform: platform, AgentVersion: version, Phrase: phrase, State: "pending", ExpiresAt: expires, CreatedAt: now}, nil
}

func (s *Service) List(ctx context.Context) ([]Request, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,installation_id,hostname,platform,agent_version,phrase,state,COALESCE(post_id,''),expires_at,created_at FROM agent_pairing_requests WHERE state IN ('pending','approved') ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Request{}
	for rows.Next() {
		var value Request
		var expires, created string
		if err = rows.Scan(&value.ID, &value.InstallationID, &value.Hostname, &value.Platform, &value.AgentVersion, &value.Phrase, &value.State, &value.PostID, &expires, &created); err != nil {
			return nil, err
		}
		value.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		value.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if value.State == "pending" && !s.now().UTC().Before(value.ExpiresAt) {
			value.State = "expired"
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Service) Connections(ctx context.Context, postID string) ([]Connection, error) {
	query := `SELECT a.installation_id,a.post_id,a.hostname,a.platform,a.agent_version,a.created_at,c.last_seen_at,c.last_sent_at,c.last_rejected_at,c.last_error,c.partial,c.revoked_at FROM agent_connections a JOIN collector_keys c ON c.id=a.installation_id WHERE 1=1`
	arguments := []any{}
	if postID != "" {
		query += ` AND a.post_id=?`
		arguments = append(arguments, postID)
	}
	query += ` ORDER BY a.hostname,a.installation_id`
	rows, err := s.s.DB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Connection{}
	now := s.now().UTC()
	for rows.Next() {
		var value Connection
		var created string
		var seen, sent, rejected, lastError, revoked sql.NullString
		var partial bool
		if err = rows.Scan(&value.InstallationID, &value.PostID, &value.Hostname, &value.Platform, &value.AgentVersion, &created, &seen, &sent, &rejected, &lastError, &partial, &revoked); err != nil {
			return nil, err
		}
		value.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		value.Status = "never_connected"
		if revoked.Valid {
			value.Status = "revoked"
		} else if rejected.Valid && (!seen.Valid || rejected.String > seen.String) {
			value.Status = "rejected"
		} else if seen.Valid {
			parsed, _ := time.Parse(time.RFC3339Nano, seen.String)
			value.LastSeenAt = &parsed
			since := now.Sub(parsed)
			if since > 10*time.Minute {
				value.Status = "offline"
			} else if since > 2*time.Minute {
				value.Status = "stale"
			} else if sent.Valid {
				sentAt, _ := time.Parse(time.RFC3339Nano, sent.String)
				difference := now.Sub(sentAt)
				if difference > 5*time.Minute || difference < (-5*time.Minute) {
					value.Status = "skewed"
				} else if partial {
					value.Status = "partial"
				} else {
					value.Status = "healthy"
				}
			} else if partial {
				value.Status = "partial"
			} else {
				value.Status = "healthy"
			}
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Service) Revoke(ctx context.Context, installationID string) error {
	now := s.now().UTC().Format(time.RFC3339Nano)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agent_connections SET revoked_at=? WHERE installation_id=? AND revoked_at IS NULL`, now, installationID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errors.New("agent connection unavailable")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE collector_keys SET revoked_at=? WHERE id=?`, now, installationID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) Rotate(ctx context.Context, installationID, current string) (string, error) {
	if installationID == "" || current == "" {
		return "", errors.New("agent credential required")
	}
	old := sha256.Sum256([]byte(current))
	credential, err := random(32)
	if err != nil {
		return "", err
	}
	next := sha256.Sum256([]byte(credential))
	result, err := s.s.DB.ExecContext(ctx, `UPDATE collector_keys SET secret_hash=?,last_error='' WHERE id=? AND secret_hash=? AND revoked_at IS NULL`, next[:], installationID, old[:])
	if err != nil {
		return "", err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return "", errors.New("agent credential rejected")
	}
	return credential, nil
}

func (s *Service) Decide(ctx context.Context, id, postID string, approve bool) error {
	now := s.now().UTC()
	state := "rejected"
	var result sql.Result
	var err error
	if approve {
		state = "approved"
		result, err = s.s.DB.ExecContext(ctx, `UPDATE agent_pairing_requests SET state=?,post_id=?,approved_at=? WHERE id=? AND state='pending' AND expires_at>? AND EXISTS(SELECT 1 FROM posts WHERE id=? AND archived=0)`, state, postID, now.Format(time.RFC3339Nano), id, now.Format(time.RFC3339Nano), postID)
	} else {
		result, err = s.s.DB.ExecContext(ctx, `UPDATE agent_pairing_requests SET state=?,terminal_at=? WHERE id=? AND state='pending' AND expires_at>?`, state, now.Format(time.RFC3339Nano), id, now.Format(time.RFC3339Nano))
	}
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errors.New("pairing request unavailable")
	}
	return nil
}

func (s *Service) Poll(ctx context.Context, id, secret string) (Enrollment, error) {
	hash := sha256.Sum256([]byte(secret))
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, err
	}
	defer tx.Rollback()
	var state, postID, installationID, hostname, platform, version, expires string
	if err = tx.QueryRowContext(ctx, `SELECT state,COALESCE(post_id,''),installation_id,hostname,platform,agent_version,expires_at FROM agent_pairing_requests WHERE id=? AND request_secret_hash=?`, id, hash[:]).Scan(&state, &postID, &installationID, &hostname, &platform, &version, &expires); err != nil {
		return Enrollment{}, errors.New("pairing request invalid")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, expires)
	if !now.Before(expiresAt) {
		return Enrollment{State: "expired"}, nil
	}
	if state != "approved" {
		return Enrollment{State: state}, nil
	}
	credential, err := random(32)
	if err != nil {
		return Enrollment{}, err
	}
	credentialHash := sha256.Sum256([]byte(credential))
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(installation_id) DO UPDATE SET post_id=excluded.post_id,hostname=excluded.hostname,platform=excluded.platform,agent_version=excluded.agent_version,revoked_at=NULL`, installationID, postID, hostname, platform, version, now.Format(time.RFC3339Nano))
	if err != nil {
		return Enrollment{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO collector_keys(id,post_id,secret_hash) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET post_id=excluded.post_id,secret_hash=excluded.secret_hash,revoked_at=NULL,last_sequence=0,last_seen_at=NULL,last_observed_at=NULL,last_sent_at=NULL,last_error='',last_rejected_at=NULL,rejected_count=0,partial=0`, installationID, postID, credentialHash[:])
	if err != nil {
		return Enrollment{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_pairing_requests SET state='consumed',terminal_at=? WHERE id=? AND state='approved'`, now.Format(time.RFC3339Nano), id)
	if err != nil {
		return Enrollment{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return Enrollment{}, errors.New("pairing request already consumed")
	}
	if err = tx.Commit(); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{State: "approved", PostID: postID, CollectorID: installationID, Credential: credential}, nil
}

func random(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
func pairingPhrase() (string, error) {
	a := []string{"amber", "cedar", "copper", "olive", "silver", "willow"}
	b := []string{"bridge", "harbor", "meadow", "river", "summit", "tower"}
	c := []string{"four", "seven", "nine", "twelve", "sixteen", "twenty"}
	raw := make([]byte, 3)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s", a[int(raw[0])%len(a)], b[int(raw[1])%len(b)], c[int(raw[2])%len(c)]), nil
}
func Bearer(value string) string { return strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")) }
