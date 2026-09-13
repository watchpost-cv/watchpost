package cluster

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
)

const PairingLifetime = 10 * time.Minute

type PairingService struct {
	s        *store.Store
	identity *IdentityService
	now      func() time.Time
}

type Invitation struct {
	ID        string    `json:"id"`
	Token     string    `json:"token,omitempty"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type JoinRequest struct {
	ID              string    `json:"id"`
	NodeID          string    `json:"node_id"`
	InstallationID  string    `json:"installation_id"`
	DisplayName     string    `json:"display_name"`
	PublicEndpoint  string    `json:"public_endpoint"`
	PublicKey       string    `json:"public_key"`
	Capabilities    []string  `json:"capabilities"`
	ProtocolVersion int       `json:"protocol_version"`
	ProductVersion  string    `json:"product_version"`
	Fingerprint     string    `json:"fingerprint"`
	State           string    `json:"state"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

type JoinSubmission struct {
	InvitationToken   string   `json:"invitation_token"`
	Identity          Identity `json:"identity"`
	CredentialForHost string   `json:"credential_for_host"`
}

type JoinReceipt struct {
	RequestID     string `json:"request_id"`
	RequestSecret string `json:"request_secret"`
	State         string `json:"state"`
}

type PairingResult struct {
	State      string    `json:"state"`
	Remote     *Identity `json:"remote,omitempty"`
	Credential string    `json:"credential,omitempty"`
}

func NewPairingService(s *store.Store, identity *IdentityService) *PairingService {
	return &PairingService{s: s, identity: identity, now: time.Now}
}

func (s *PairingService) Invite(ctx context.Context, entry audit.Entry) (Invitation, error) {
	id, err := randomID("inv_", 12)
	if err != nil {
		return Invitation{}, err
	}
	token, err := randomSecret(32)
	if err != nil {
		return Invitation{}, err
	}
	hash := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	expires := now.Add(PairingLifetime)
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO cluster_invitations(id,token_hash,state,expires_at,created_at) VALUES(?,?,'pending',?,?)`, id, hash[:], expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return Invitation{}, err
	}
	entry.Action = "cluster_invite_create"
	entry.ObjectType = "cluster_invitation"
	entry.ObjectID = id
	entry.Detail = "short-lived single-use invitation created"
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Invitation{}, err
	}
	if err = tx.Commit(); err != nil {
		return Invitation{}, err
	}
	return Invitation{ID: id, Token: token, State: "pending", ExpiresAt: expires, CreatedAt: now}, nil
}

func (s *PairingService) SubmitJoin(ctx context.Context, in JoinSubmission) (JoinReceipt, error) {
	if in.InvitationToken == "" || in.Identity.NodeID == "" || in.Identity.InstallationID == "" || in.Identity.PublicKey == "" || in.Identity.PublicEndpoint == "" || !strings.HasPrefix(in.Identity.PublicEndpoint, "https://") || len(in.CredentialForHost) < 32 {
		return JoinReceipt{}, errors.New("invalid cluster join request")
	}
	tokenHash := sha256.Sum256([]byte(in.InvitationToken))
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return JoinReceipt{}, err
	}
	defer tx.Rollback()
	var inviteID, expiresText, state string
	if err = tx.QueryRowContext(ctx, `SELECT id,expires_at,state FROM cluster_invitations WHERE token_hash=?`, tokenHash[:]).Scan(&inviteID, &expiresText, &state); err != nil {
		return JoinReceipt{}, errors.New("invitation unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if state != "pending" || !expires.After(now) {
		_, _ = tx.ExecContext(ctx, `UPDATE cluster_invitations SET state='expired' WHERE id=? AND state='pending'`, inviteID)
		return JoinReceipt{}, errors.New("invitation expired or consumed")
	}
	local, err := s.identity.Ensure(ctx, "")
	if err != nil {
		return JoinReceipt{}, err
	}
	if local.NodeID == in.Identity.NodeID || local.InstallationID == in.Identity.InstallationID {
		return JoinReceipt{}, errors.New("cannot pair node with itself")
	}
	requestID, err := randomID("join_", 12)
	if err != nil {
		return JoinReceipt{}, err
	}
	requestSecret, err := randomSecret(32)
	if err != nil {
		return JoinReceipt{}, err
	}
	requestHash := sha256.Sum256([]byte(requestSecret))
	caps, _ := json.Marshal(uniqueStrings(in.Identity.Capabilities))
	pub, err := base64.RawURLEncoding.DecodeString(in.Identity.PublicKey)
	if err != nil {
		return JoinReceipt{}, errors.New("invalid node public key")
	}
	requestExpires := now.Add(PairingLifetime)
	_, err = tx.ExecContext(ctx, `INSERT INTO cluster_join_requests(id,request_secret_hash,invitation_id,node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,credential_for_local,state,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'pending',?,?)`, requestID, requestHash[:], inviteID, in.Identity.NodeID, in.Identity.InstallationID, in.Identity.DisplayName, strings.TrimRight(in.Identity.PublicEndpoint, "/"), pub, string(caps), in.Identity.ProtocolVersion, in.Identity.ProductVersion, in.CredentialForHost, requestExpires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return JoinReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE cluster_invitations SET state='consumed',consumed_at=? WHERE id=? AND state='pending'`, now.Format(time.RFC3339Nano), inviteID); err != nil {
		return JoinReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return JoinReceipt{}, err
	}
	return JoinReceipt{RequestID: requestID, RequestSecret: requestSecret, State: "pending"}, nil
}

func (s *PairingService) ListPending(ctx context.Context) ([]JoinRequest, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,expires_at,created_at FROM cluster_join_requests WHERE state='pending' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JoinRequest
	for rows.Next() {
		v, err := scanJoin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PairingService) Decide(ctx context.Context, id string, approve bool, entry audit.Entry) (string, error) {
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var nodeID, installationID, name, endpoint, caps, product, credentialForLocal, expiresText string
	var public []byte
	var protocol int
	err = tx.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,credential_for_local,expires_at FROM cluster_join_requests WHERE id=? AND state='pending'`, id).Scan(&nodeID, &installationID, &name, &endpoint, &public, &caps, &protocol, &product, &credentialForLocal, &expiresText)
	if err != nil {
		return "", errors.New("pending join request unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if !expires.After(now) {
		return "", errors.New("join request expired")
	}
	state := "rejected"
	responseCredential := ""
	if approve {
		state = "approved"
		responseCredential, err = randomSecret(32)
		if err != nil {
			return "", err
		}
		inboundHash := sha256.Sum256([]byte(responseCredential))
		_, err = tx.ExecContext(ctx, `INSERT INTO cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,inbound_secret_hash,outbound_secret,state,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?) ON CONFLICT(node_id) DO UPDATE SET installation_id=excluded.installation_id,display_name=excluded.display_name,public_endpoint=excluded.public_endpoint,public_key=excluded.public_key,capabilities_json=excluded.capabilities_json,protocol_version=excluded.protocol_version,product_version=excluded.product_version,inbound_secret_hash=excluded.inbound_secret_hash,outbound_secret=excluded.outbound_secret,state='active',paired_at=excluded.paired_at,revoked_at=NULL`, nodeID, installationID, name, endpoint, public, caps, protocol, product, inboundHash[:], credentialForLocal, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		if err != nil {
			return "", err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE cluster_join_requests SET state=?,decided_at=? WHERE id=? AND state='pending'`, state, now.Format(time.RFC3339Nano), id); err != nil {
		return "", err
	}
	entry.Action = "cluster_join_" + state
	entry.ObjectType = "cluster_join_request"
	entry.ObjectID = id
	entry.Detail = "node=" + nodeID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return responseCredential, nil
}

func (s *PairingService) Poll(ctx context.Context, id, secret string) (PairingResult, error) {
	hash := sha256.Sum256([]byte(secret))
	now := s.now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return PairingResult{}, err
	}
	defer tx.Rollback()
	var state, nodeID, installationID, name, endpoint, caps, product, credential, expiresText string
	var public []byte
	var protocol int
	var consumed sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT state,node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,expires_at,response_consumed_at FROM cluster_join_requests WHERE id=? AND request_secret_hash=?`, id, hash[:]).Scan(&state, &nodeID, &installationID, &name, &endpoint, &public, &caps, &protocol, &product, &expiresText, &consumed)
	if err != nil {
		return PairingResult{}, errors.New("join request unavailable")
	}
	expires, _ := time.Parse(time.RFC3339Nano, expiresText)
	if state == "pending" && !expires.After(now) {
		return PairingResult{State: "expired"}, nil
	}
	if state == "rejected" {
		return PairingResult{State: "rejected"}, nil
	}
	if state != "approved" {
		return PairingResult{State: state}, nil
	}
	if consumed.Valid {
		return PairingResult{}, errors.New("pairing result already collected")
	}
	var outbound string
	if err = tx.QueryRowContext(ctx, `SELECT inbound_secret_hash FROM cluster_members WHERE node_id=?`, nodeID).Scan(new([]byte)); err != nil {
		return PairingResult{}, err
	}
	// The approval credential is not stored in plaintext. Re-issue it once by rotating
	// the just-created inbound hash to a fresh secret before collection.
	credential, err = randomSecret(32)
	if err != nil {
		return PairingResult{}, err
	}
	newHash := sha256.Sum256([]byte(credential))
	if _, err = tx.ExecContext(ctx, `UPDATE cluster_members SET inbound_secret_hash=? WHERE node_id=?`, newHash[:], nodeID); err != nil {
		return PairingResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE cluster_join_requests SET state='consumed',response_consumed_at=? WHERE id=?`, now.Format(time.RFC3339Nano), id); err != nil {
		return PairingResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return PairingResult{}, err
	}
	host, err := s.identity.Ensure(ctx, "")
	if err != nil {
		return PairingResult{}, err
	}
	_ = nodeID
	_ = installationID
	_ = name
	_ = endpoint
	_ = public
	_ = caps
	_ = protocol
	_ = product
	_ = outbound
	return PairingResult{State: "approved", Remote: &host, Credential: credential}, nil
}

func (s *PairingService) AcceptRemote(ctx context.Context, remote Identity, outboundCredential, inboundCredential string) error {
	if remote.NodeID == "" || outboundCredential == "" || inboundCredential == "" {
		return errors.New("incomplete pairing result")
	}
	public, err := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	if err != nil {
		return err
	}
	caps, _ := json.Marshal(uniqueStrings(remote.Capabilities))
	hash := sha256.Sum256([]byte(inboundCredential))
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,inbound_secret_hash,outbound_secret,state,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?) ON CONFLICT(node_id) DO UPDATE SET installation_id=excluded.installation_id,display_name=excluded.display_name,public_endpoint=excluded.public_endpoint,public_key=excluded.public_key,capabilities_json=excluded.capabilities_json,protocol_version=excluded.protocol_version,product_version=excluded.product_version,inbound_secret_hash=excluded.inbound_secret_hash,outbound_secret=excluded.outbound_secret,state='active',paired_at=excluded.paired_at,revoked_at=NULL`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, public, string(caps), remote.ProtocolVersion, remote.ProductVersion, hash[:], outboundCredential, now, now)
	return err
}

func scanJoin(scanner interface{ Scan(...any) error }) (JoinRequest, error) {
	var v JoinRequest
	var pub []byte
	var caps, expires, created string
	if err := scanner.Scan(&v.ID, &v.NodeID, &v.InstallationID, &v.DisplayName, &v.PublicEndpoint, &pub, &caps, &v.ProtocolVersion, &v.ProductVersion, &v.State, &expires, &created); err != nil {
		return v, err
	}
	v.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	_ = json.Unmarshal([]byte(caps), &v.Capabilities)
	v.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.Fingerprint = fingerprint(pub)
	return v, nil
}
func fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return fmt.Sprintf("%x", sum[:8])
}
func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
