package cluster

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

	"github.com/watchpost-cv/watchpost/internal/store"
)

const MaxRequestBytes = corecluster.MaxRequestBytes
const ClockSkew = corecluster.ClockSkew

const (
	headerNode       = "X-Watchpost-Node"
	headerTimestamp  = "X-Watchpost-Timestamp"
	headerNonce      = "X-Watchpost-Nonce"
	headerRequestID  = "X-Watchpost-Request-ID"
	headerSignature  = "X-Watchpost-Signature"
	headerProtocol   = "X-Watchpost-Protocol"
	headerCapability = "X-Watchpost-Capability"
)

type Transport struct {
	s        *store.Store
	identity *IdentityService
	client   *http.Client
	now      func() time.Time
}

type AuthenticatedRequest struct {
	NodeID     string
	RequestID  string
	Capability string
	Body       []byte
	ReceivedAt time.Time
}

func NewTransport(s *store.Store, identity *IdentityService) *Transport {
	return &Transport{s: s, identity: identity, client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
}
func (t *Transport) SetHTTPClient(client *http.Client) {
	if client != nil {
		t.client = client
	}
}

func (t *Transport) Authenticate(r *http.Request, requiredCapability string) (AuthenticatedRequest, error) {
	nodeID := r.Header.Get(headerNode)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	requestID := r.Header.Get(headerRequestID)
	signature := r.Header.Get(headerSignature)
	if nodeID == "" || timestamp == "" || nonce == "" || requestID == "" || signature == "" {
		return AuthenticatedRequest{}, errors.New("cluster authentication required")
	}
	protocol, err := strconv.Atoi(r.Header.Get(headerProtocol))
	if err != nil {
		return AuthenticatedRequest{}, errors.New("incompatible cluster protocol")
	}
	at, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return AuthenticatedRequest{}, errors.New("invalid cluster timestamp")
	}
	var hash, pendingHash []byte
	var state, caps string
	var pendingExpires sql.NullString
	if err = t.s.DB.QueryRowContext(r.Context(), `SELECT inbound_secret_hash,pending_inbound_secret_hash,pending_inbound_expires_at,state,capabilities_json FROM cluster_members WHERE node_id=?`, nodeID).Scan(&hash, &pendingHash, &pendingExpires, &state, &caps); err != nil {
		return AuthenticatedRequest{}, errors.New("cluster member unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		return AuthenticatedRequest{}, err
	}
	var capabilities []string
	_ = json.Unmarshal([]byte(caps), &capabilities)
	var pendingExpiry *time.Time
	if pendingExpires.Valid {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, pendingExpires.String); parseErr == nil {
			pendingExpiry = &parsed
		}
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	verified, err := corecluster.VerifyIncoming(corecluster.VerifyRequestInput{
		Material:           corecluster.AuthMaterial{State: state, Protocol: protocol, Capabilities: capabilities, CurrentHash: hash, PendingHash: pendingHash, PendingExpires: pendingExpiry},
		RequiredCapability: requiredCapability, PresentedSecret: secret, Method: r.Method, RequestURI: r.URL.RequestURI(),
		Envelope: corecluster.RequestEnvelope{NodeID: nodeID, Timestamp: at, Nonce: nonce, RequestID: requestID, Protocol: protocol, Capability: r.Header.Get(headerCapability), Signature: signature},
		Body:     body, Now: t.now(),
	})
	if err != nil {
		return AuthenticatedRequest{}, err
	}
	pending := verified.PromotePending
	if pending {
		if _, err = t.s.DB.ExecContext(r.Context(), `UPDATE cluster_members SET inbound_secret_hash=pending_inbound_secret_hash,pending_inbound_secret_hash=NULL,pending_inbound_expires_at=NULL,credential_version=credential_version+1 WHERE node_id=?`, nodeID); err != nil {
			return AuthenticatedRequest{}, err
		}
	}
	cutoff := t.now().UTC().Add(-2 * ClockSkew).Format(time.RFC3339Nano)
	_, _ = t.s.DB.ExecContext(r.Context(), `DELETE FROM cluster_nonces WHERE seen_at<?`, cutoff)
	if _, err = t.s.DB.ExecContext(r.Context(), `INSERT INTO cluster_nonces(node_id,nonce,seen_at) VALUES(?,?,?)`, nodeID, nonce, t.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return AuthenticatedRequest{}, errors.New("cluster replay rejected")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return AuthenticatedRequest{NodeID: nodeID, RequestID: requestID, Capability: requiredCapability, Body: body, ReceivedAt: t.now().UTC()}, nil
}

func (t *Transport) Do(ctx context.Context, nodeID, method, path, capability string, body []byte) (*http.Response, error) {
	if int64(len(body)) > MaxRequestBytes {
		return nil, errors.New("cluster request too large")
	}
	var endpoint, secret, state string
	var protocol int
	if err := t.s.DB.QueryRowContext(ctx, `SELECT public_endpoint,outbound_secret,state,protocol_version FROM cluster_members WHERE node_id=?`, nodeID).Scan(&endpoint, &secret, &state, &protocol); err != nil {
		return nil, err
	}
	if state != "active" {
		return nil, errors.New("cluster member unavailable")
	}
	if protocol != ProtocolVersion {
		return nil, errors.New("incompatible cluster protocol")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("cluster endpoint must use https")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := strings.TrimRight(endpoint, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	local, err := t.identity.Ensure(ctx, "")
	if err != nil {
		return nil, err
	}
	timestamp := t.now().UTC().Format(time.RFC3339Nano)
	nonce, err := corecluster.NewSecret(18)
	if err != nil {
		return nil, err
	}
	requestID, err := randomID("req_", 12)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set(headerNode, local.NodeID)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerRequestID, requestID)
	req.Header.Set(headerProtocol, strconv.Itoa(ProtocolVersion))
	req.Header.Set(headerCapability, capability)
	req.Header.Set(headerSignature, corecluster.Signature(secret, method, req.URL.RequestURI(), timestamp, nonce, requestID, capability, body))
	req.Header.Set("Content-Type", "application/json")
	started := t.now()
	resp, err := t.client.Do(req)
	latency := t.now().Sub(started)
	if err != nil {
		return nil, err
	}
	_, _ = t.s.DB.ExecContext(ctx, `UPDATE cluster_members SET last_seen_at=?,last_latency_ms=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), latency.Milliseconds(), nodeID)
	return resp, nil
}
