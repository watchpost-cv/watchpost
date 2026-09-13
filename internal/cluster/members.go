package cluster

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
)

const RotationLifetime = 10 * time.Minute

type Member struct {
	NodeID            string     `json:"node_id"`
	InstallationID    string     `json:"installation_id"`
	DisplayName       string     `json:"display_name"`
	PublicEndpoint    string     `json:"public_endpoint"`
	PublicKey         string     `json:"public_key"`
	Capabilities      []string   `json:"capabilities"`
	ProtocolVersion   int        `json:"protocol_version"`
	ProductVersion    string     `json:"product_version"`
	State             string     `json:"state"`
	Health            string     `json:"health"`
	Compatible        bool       `json:"compatible"`
	CreatedAt         time.Time  `json:"created_at"`
	PairedAt          time.Time  `json:"paired_at"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	LastLatencyMS     *int64     `json:"last_latency_ms,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	CredentialVersion int        `json:"credential_version"`
}

type MemberService struct {
	s   *store.Store
	now func() time.Time
}

func NewMemberService(s *store.Store) *MemberService { return &MemberService{s: s, now: time.Now} }

func (s *MemberService) List(ctx context.Context) ([]Member, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,created_at,paired_at,last_seen_at,last_latency_ms,revoked_at,credential_version FROM cluster_members ORDER BY display_name,node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		var public []byte
		var caps, created, paired string
		var seen, revoked sql.NullString
		var latency sql.NullInt64
		if err = rows.Scan(&m.NodeID, &m.InstallationID, &m.DisplayName, &m.PublicEndpoint, &public, &caps, &m.ProtocolVersion, &m.ProductVersion, &m.State, &created, &paired, &seen, &latency, &revoked, &m.CredentialVersion); err != nil {
			return nil, err
		}
		m.PublicKey = base64.RawURLEncoding.EncodeToString(public)
		_ = json.Unmarshal([]byte(caps), &m.Capabilities)
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		m.PairedAt, _ = time.Parse(time.RFC3339Nano, paired)
		m.LastSeenAt = parseNullTime(seen)
		m.RevokedAt = parseNullTime(revoked)
		if latency.Valid {
			v := latency.Int64
			m.LastLatencyMS = &v
		}
		m.Compatible = m.ProtocolVersion == ProtocolVersion
		m.Health = memberHealth(m, s.now().UTC())
		out = append(out, m)
	}
	return out, rows.Err()
}

func memberHealth(m Member, now time.Time) string {
	if m.State == "revoked" {
		return "revoked"
	}
	if m.State == "disabled" {
		return "disabled"
	}
	if !m.Compatible {
		return "incompatible"
	}
	if m.LastSeenAt == nil {
		return "unknown"
	}
	age := now.Sub(*m.LastSeenAt)
	if age > 10*time.Minute {
		return "offline"
	}
	if age > 2*time.Minute {
		return "degraded"
	}
	return "online"
}

func (s *MemberService) SetEnabled(ctx context.Context, nodeID string, enabled bool, entry audit.Entry) error {
	state := "disabled"
	if enabled {
		state = "active"
	}
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE cluster_members SET state=? WHERE node_id=? AND state!='revoked'`, state, nodeID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	entry.Action = "cluster_member_" + state
	entry.ObjectType = "cluster_member"
	entry.ObjectID = nodeID
	entry.Detail = state
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *MemberService) Revoke(ctx context.Context, nodeID string, entry audit.Entry) error {
	now := s.now().UTC().Format(time.RFC3339Nano)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE cluster_members SET state='revoked',revoked_at=?,pending_inbound_secret_hash=NULL,pending_inbound_expires_at=NULL WHERE node_id=? AND state!='revoked'`, now, nodeID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	entry.Action = "cluster_member_revoke"
	entry.ObjectType = "cluster_member"
	entry.ObjectID = nodeID
	entry.Detail = "revoked"
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *MemberService) Remove(ctx context.Context, nodeID string, entry audit.Entry) error {
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM cluster_members WHERE node_id=?`, nodeID).Scan(&state); err != nil {
		return errors.New("cluster member unavailable")
	}
	if state == "active" {
		return errors.New("disable or revoke member before removal")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM cluster_members WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	entry.Action = "cluster_member_remove"
	entry.ObjectType = "cluster_member"
	entry.ObjectID = nodeID
	entry.Detail = "removed"
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *MemberService) RotateInbound(ctx context.Context, nodeID string, entry audit.Entry) (string, error) {
	secret, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(secret))
	expires := s.now().UTC().Add(RotationLifetime).Format(time.RFC3339Nano)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id=? AND state='active'`, hash[:], expires, nodeID)
	if err != nil {
		return "", err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return "", errors.New("active cluster member unavailable")
	}
	entry.Action = "cluster_credential_rotate_start"
	entry.ObjectType = "cluster_member"
	entry.ObjectID = nodeID
	entry.Detail = "overlap credential issued"
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return secret, nil
}
func (s *MemberService) SetOutboundCredential(ctx context.Context, nodeID, secret string) error {
	if len(secret) < 32 {
		return errors.New("invalid cluster credential")
	}
	result, err := s.s.DB.ExecContext(ctx, `UPDATE cluster_members SET outbound_secret=?,credential_version=credential_version+1 WHERE node_id=? AND state='active'`, secret, nodeID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("active cluster member unavailable")
	}
	return nil
}
