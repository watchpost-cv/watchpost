package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
)

const PairingLifetime = corecluster.PairingLifetime

type Invitation = corecluster.Invitation
type JoinRequest = corecluster.JoinRequest
type JoinSubmission = corecluster.JoinSubmission
type JoinReceipt = corecluster.JoinReceipt
type PairingResult = corecluster.PairingResult

type PairingService struct {
	s        *store.Store
	identity *IdentityService
	now      func() time.Time
}

func NewPairingService(s *store.Store, identity *IdentityService) *PairingService {
	return &PairingService{s: s, identity: identity, now: time.Now}
}

func (s *PairingService) Invite(ctx context.Context, entry audit.Entry) (Invitation, error) {
	id, err := randomID("inv_", 12)
	if err != nil {
		return Invitation{}, err
	}
	token, err := corecluster.NewSecret(32)
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
	if err := corecluster.ValidateJoinSubmission(in, s.now().UTC()); err != nil {
		return JoinReceipt{}, err
	}
	if in.InvitationToken == "" || in.Identity.NodeID == "" || in.Identity.InstallationID == "" || in.Identity.PublicKey == "" || in.Identity.PublicEndpoint == "" || !strings.HasPrefix(in.Identity.PublicEndpoint, "https://") || len(in.CredentialForHost) < 32 {
		return JoinReceipt{}, errors.New("invalid cluster join request")
	}
	local, err := s.identity.Ensure(ctx, "")
	if err != nil {
		return JoinReceipt{}, err
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
	if local.NodeID == in.Identity.NodeID || local.InstallationID == in.Identity.InstallationID {
		return JoinReceipt{}, errors.New("cannot pair node with itself")
	}
	requestID, err := randomID("join_", 12)
	if err != nil {
		return JoinReceipt{}, err
	}
	requestSecret, err := corecluster.NewSecret(32)
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
		responseCredential, err = corecluster.NewSecret(32)
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
	host, err := s.identity.Ensure(ctx, "")
	if err != nil {
		return PairingResult{}, err
	}
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
	credential, err = corecluster.NewSecret(32)
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

type OutboundJoin struct {
	ID        string    `json:"id"`
	RemoteURL string    `json:"remote_url"`
	RequestID string    `json:"request_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *PairingService) BeginOutbound(ctx context.Context, remoteURL, invitationToken string, client *http.Client) (OutboundJoin, error) {
	remoteURL = strings.TrimRight(strings.TrimSpace(remoteURL), "/")
	parsed, err := url.Parse(remoteURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return OutboundJoin{}, errors.New("remote Watchpost URL must use https")
	}
	local, err := s.identity.Ensure(ctx, "")
	if err != nil {
		return OutboundJoin{}, err
	}
	if local.PublicEndpoint == "" {
		return OutboundJoin{}, errors.New("configure this Watchpost public HTTPS endpoint before joining a cluster")
	}
	localCredential, err := corecluster.NewSecret(32)
	if err != nil {
		return OutboundJoin{}, err
	}
	payload, _ := json.Marshal(JoinSubmission{InvitationToken: invitationToken, Identity: local, CredentialForHost: localCredential})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteURL+"/api/cluster/v1/join", bytes.NewReader(payload))
	if err != nil {
		return OutboundJoin{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return OutboundJoin{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return OutboundJoin{}, fmt.Errorf("remote join returned %s", resp.Status)
	}
	var receipt JoinReceipt
	if err = json.NewDecoder(io.LimitReader(resp.Body, MaxRequestBytes)).Decode(&receipt); err != nil {
		return OutboundJoin{}, err
	}
	id, err := randomID("out_", 12)
	if err != nil {
		return OutboundJoin{}, err
	}
	now := s.now().UTC()
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO cluster_outbound_joins(id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?)`, id, remoteURL, receipt.RequestID, receipt.RequestSecret, localCredential, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return OutboundJoin{}, err
	}
	return OutboundJoin{ID: id, RemoteURL: remoteURL, RequestID: receipt.RequestID, State: "pending", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *PairingService) ListOutbound(ctx context.Context) ([]OutboundJoin, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,remote_url,request_id,state,created_at,updated_at,last_error FROM cluster_outbound_joins ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboundJoin
	for rows.Next() {
		var v OutboundJoin
		var c, u string
		if err = rows.Scan(&v.ID, &v.RemoteURL, &v.RequestID, &v.State, &c, &u, &v.LastError); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339Nano, c)
		v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, u)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PairingService) CollectOutbound(ctx context.Context, id string, client *http.Client) (OutboundJoin, error) {
	var v OutboundJoin
	var requestSecret, localCredential, created, updated string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at,last_error FROM cluster_outbound_joins WHERE id=?`, id).Scan(&v.ID, &v.RemoteURL, &v.RequestID, &requestSecret, &localCredential, &v.State, &created, &updated, &v.LastError)
	if err != nil {
		return v, errors.New("outbound join unavailable")
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if v.State != "pending" {
		return v, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.RemoteURL+"/api/cluster/v1/join/"+url.PathEscape(v.RequestID), nil)
	if err != nil {
		return v, err
	}
	req.Header.Set("Authorization", "Bearer "+requestSecret)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("remote pairing status returned %s", resp.Status)
	}
	var result PairingResult
	if err = json.NewDecoder(io.LimitReader(resp.Body, MaxRequestBytes)).Decode(&result); err != nil {
		return v, err
	}
	now := s.now().UTC()
	switch result.State {
	case "approved":
		if result.Remote == nil || result.Credential == "" {
			return v, errors.New("remote approval was incomplete")
		}
		if err = s.AcceptRemote(ctx, *result.Remote, result.Credential, localCredential); err != nil {
			return v, err
		}
		v.State = "approved"
	case "rejected", "expired":
		v.State = result.State
	default:
		v.State = "pending"
	}
	v.UpdatedAt = now
	_, err = s.s.DB.ExecContext(ctx, `UPDATE cluster_outbound_joins SET state=?,updated_at=?,last_error='' WHERE id=?`, v.State, now.Format(time.RFC3339Nano), id)
	return v, err
}
