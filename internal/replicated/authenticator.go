// Package replicated's WatchpostAuthenticator is the CP7D-4a production
// security integration: it implements replication.PeerAuthenticator,
// MembershipChecker and CapabilitySource over the real Watchpost
// cluster_members / cluster_nonces tables, reusing the existing Gantry
// credential lifecycle and durable purpose-scoped handshake replay. The
// reference MemoryPeerAuthenticator/MemoryMembership remain test-only.
package replicated

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

const (
	replicationCapability = "replication"
	// replayPurposePrefix scopes replication-handshake nonces in cluster_nonces
	// so they cannot collide with ordinary signed-RPC nonces (effective replay
	// identity: peer + purpose + nonce, using the existing table + pruning).
	replayPurposePrefix = "repl-handshake:"
	handshakeSkewWindow = 5 * time.Minute
)

// WatchpostAuthenticator verifies connection-establishment handshakes against
// cluster_members credential hashes (current or pending, with promotion on
// successful proof per the existing Watchpost lifecycle), provides membership
// revalidation and authenticated capabilities, and consumes handshake nonces
// into cluster_nonces under a purpose-scoped key.
type WatchpostAuthenticator struct {
	db           *sql.DB
	protocol     int
	now          func() time.Time
	localID      raft.ServerID
	localCaps    string
	localRevoked bool
}

var (
	_ replication.PeerAuthenticator    = (*WatchpostAuthenticator)(nil)
	_ replication.MembershipChecker    = (*WatchpostAuthenticator)(nil)
	_ replication.CapabilitySource     = (*WatchpostAuthenticator)(nil)
	_ replication.PeerCredentialSource = (*WatchpostAuthenticator)(nil)
)

// NewWatchpostAuthenticator returns the production authenticator over db. It
// reads the local node identity and authenticated capabilities from the
// singleton cluster_identity row (the node itself is not a cluster_members row)
// so the voter schema gate can resolve the leader's own capabilities.
func NewWatchpostAuthenticator(db *sql.DB, protocol int) *WatchpostAuthenticator {
	a := &WatchpostAuthenticator{db: db, protocol: protocol, now: time.Now}
	var nid string
	var caps string
	var revoked sql.NullString
	if err := db.QueryRow(`SELECT node_id,capabilities_json,revoked_at FROM cluster_identity WHERE singleton=1`).Scan(&nid, &caps, &revoked); err == nil {
		a.localID = raft.ServerID(nid)
		a.localCaps = caps
		a.localRevoked = revoked.Valid && revoked.String != ""
	}
	return a
}

// OutboundCredential implements replication.PeerCredentialSource: the
// credential this node presents to peer is that peer's cluster_members
// outbound_secret (pairwise - different per peer). Resolved per connection so
// a reconnect after outbound rotation uses the current credential.
func (a *WatchpostAuthenticator) OutboundCredential(ctx context.Context, peer raft.ServerID) (string, error) {
	var secret string
	if err := a.db.QueryRowContext(ctx, `SELECT outbound_secret FROM cluster_members WHERE node_id=?`, string(peer)).Scan(&secret); err != nil {
		return "", fmt.Errorf("outbound credential for %s: %w", peer, err)
	}
	return secret, nil
}

type memberRow struct {
	inboundHash []byte
	pendingHash []byte
	pendingExp  sql.NullString
	state       string
	capsJSON    string
}

func (a *WatchpostAuthenticator) loadMember(ctx context.Context, nodeID string) (memberRow, error) {
	var m memberRow
	err := a.db.QueryRowContext(ctx,
		`SELECT inbound_secret_hash,pending_inbound_secret_hash,pending_inbound_expires_at,state,capabilities_json FROM cluster_members WHERE node_id=?`,
		nodeID).Scan(&m.inboundHash, &m.pendingHash, &m.pendingExp, &m.state, &m.capsJSON)
	return m, err
}

// Authenticate implements replication.PeerAuthenticator (accepting side). It
// verifies the presented secret's digest against the member's current or
// pending inbound credential, verifies the handshake signature, promotes a
// successfully proven pending credential (the existing Watchpost transition),
// and consumes the nonce durably (purpose-scoped) as replay protection.
func (a *WatchpostAuthenticator) Authenticate(ctx context.Context, in replication.AuthRequest) (replication.AuthResult, error) {
	if in.RaftServerID != in.NodeID {
		return replication.AuthResult{}, errors.New("raft server identity does not match authenticated node identity")
	}
	if in.Protocol != a.protocol {
		return replication.AuthResult{}, errors.New("incompatible replication protocol")
	}
	if !a.fresh(in.Timestamp) {
		return replication.AuthResult{}, errors.New("handshake outside clock-skew window")
	}
	m, err := a.loadMember(ctx, string(in.NodeID))
	if err != nil {
		return replication.AuthResult{}, errors.New("replication member unknown")
	}
	if m.state != "active" {
		return replication.AuthResult{}, errors.New("replication member not active")
	}
	if !hasReplicationCapability(m.capsJSON) {
		return replication.AuthResult{}, errors.New("replication not authorized for member")
	}
	if len(in.PresentedSecret) == 0 {
		return replication.AuthResult{}, errors.New("replication credential required")
	}
	digest := sha256.Sum256([]byte(in.PresentedSecret))
	promote := false
	switch {
	case equalDigest(digest[:], m.inboundHash):
		// current credential accepted
	case len(m.pendingHash) > 0 && m.pendingExp.Valid && a.pendingValid(m.pendingExp.String) && equalDigest(digest[:], m.pendingHash):
		promote = true
	default:
		return replication.AuthResult{}, errors.New("replication credential rejected")
	}
	if !replication.VerifyHandshakeSignature(in.PresentedSecret, in) {
		return replication.AuthResult{}, errors.New("invalid replication handshake signature")
	}
	if promote {
		// Existing Watchpost promotion semantic: a successfully proven pending
		// credential becomes current, pending fields clear, credential_version
		// advances. This is the same transition signed peer RPC performs.
		if _, err := a.db.ExecContext(ctx,
			`UPDATE cluster_members SET inbound_secret_hash=pending_inbound_secret_hash,pending_inbound_secret_hash=NULL,pending_inbound_expires_at=NULL,credential_version=credential_version+1 WHERE node_id=?`,
			string(in.NodeID)); err != nil {
			return replication.AuthResult{}, err
		}
	}
	if err := a.consumeNonce(ctx, string(in.NodeID), in.Nonce); err != nil {
		return replication.AuthResult{}, err
	}
	return replication.AuthResult{Allowed: true, ServerAddress: in.RaftServerAddr}, nil
}

// VerifyPeer implements replication.PeerAuthenticator (dialing side): the
// accepting node must prove it is exactly the expected node, using the
// presented secret verified against the client's stored inbound credential for
// that peer.
func (a *WatchpostAuthenticator) VerifyPeer(ctx context.Context, expected raft.ServerID, in replication.AuthRequest) error {
	if expected == "" {
		return errors.New("expected peer identity is empty")
	}
	if in.NodeID != expected || in.RaftServerID != expected {
		return fmt.Errorf("peer authenticated as %q but expected %q", in.NodeID, expected)
	}
	if in.Protocol != a.protocol {
		return errors.New("incompatible replication protocol")
	}
	if !a.fresh(in.Timestamp) {
		return errors.New("handshake outside clock-skew window")
	}
	m, err := a.loadMember(ctx, string(expected))
	if err != nil {
		return errors.New("replication member unknown")
	}
	if m.state != "active" {
		return errors.New("replication member not active")
	}
	if !hasReplicationCapability(m.capsJSON) {
		return errors.New("replication not authorized for member")
	}
	if len(in.PresentedSecret) == 0 {
		return errors.New("replication credential required")
	}
	digest := sha256.Sum256([]byte(in.PresentedSecret))
	promote := false
	switch {
	case equalDigest(digest[:], m.inboundHash):
		// current credential accepted
	case len(m.pendingHash) > 0 && m.pendingExp.Valid && a.pendingValid(m.pendingExp.String) && equalDigest(digest[:], m.pendingHash):
		promote = true
	default:
		return errors.New("replication credential rejected")
	}
	if !replication.VerifyHandshakeSignature(in.PresentedSecret, in) {
		return errors.New("invalid replication handshake signature")
	}
	if promote {
		if _, err := a.db.ExecContext(ctx,
			`UPDATE cluster_members SET inbound_secret_hash=pending_inbound_secret_hash,pending_inbound_secret_hash=NULL,pending_inbound_expires_at=NULL,credential_version=credential_version+1 WHERE node_id=?`,
			string(expected)); err != nil {
			return err
		}
	}
	if err := a.consumeNonce(ctx, string(expected), in.Nonce); err != nil {
		return err
	}
	return nil
}

// Membership implements replication.MembershipChecker for revalidation: state,
// replication authorization and protocol compatibility derive from
// cluster_members (authenticated); the local node derives from cluster_identity.
func (a *WatchpostAuthenticator) Membership(ctx context.Context, nodeID raft.ServerID) (replication.MembershipStatus, error) {
	if nodeID == a.localID {
		st := replication.MembershipActive
		if a.localRevoked {
			st = replication.MembershipRevoked
		}
		return replication.MembershipStatus{
			State:              st,
			Capabilities:       a.capabilitiesOf(nodeID, a.localCaps),
			Protocol:           a.protocol,
			ReplicationEnabled: hasReplicationCapability(a.localCaps),
		}, nil
	}
	m, err := a.loadMember(ctx, string(nodeID))
	if err != nil {
		return replication.MembershipStatus{}, errors.New("replication member unknown")
	}
	st := replication.MembershipActive
	switch m.state {
	case "disabled":
		st = replication.MembershipDisabled
	case "revoked":
		st = replication.MembershipRevoked
	}
	return replication.MembershipStatus{
		State:              st,
		Capabilities:       a.capabilitiesOf(nodeID, m.capsJSON),
		Protocol:           a.protocol,
		ReplicationEnabled: hasReplicationCapability(m.capsJSON),
	}, nil
}

// CapabilitiesOf implements replication.CapabilitySource from authenticated
// cluster_members state (and cluster_identity for the local node).
func (a *WatchpostAuthenticator) CapabilitiesOf(id raft.ServerID) (replication.Capabilities, bool) {
	if id == a.localID {
		return a.capabilitiesOf(id, a.localCaps), true
	}
	m, err := a.loadMember(context.Background(), string(id))
	if err != nil {
		return replication.Capabilities{}, false
	}
	return a.capabilitiesOf(id, m.capsJSON), true
}

func (a *WatchpostAuthenticator) capabilitiesOf(id raft.ServerID, capsJSON string) replication.Capabilities {
	c := replication.Capabilities{ID: id}
	if !hasReplicationCapability(capsJSON) {
		return c
	}
	for v := 1; v <= replication.Version; v++ {
		c.OperationSchemaVersions = append(c.OperationSchemaVersions, v)
	}
	c.SnapshotFormatVersions = []int{replication.SnapshotFormatVersion}
	return c
}

// consumeNonce durably records a handshake nonce under the purpose-scoped key,
// pruning expired entries (reusing cluster_nonces).
func (a *WatchpostAuthenticator) consumeNonce(ctx context.Context, nodeID, nonce string) error {
	if _, err := a.db.ExecContext(ctx, `DELETE FROM cluster_nonces WHERE seen_at<?`, a.now().UTC().Add(-handshakeSkewWindow).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO cluster_nonces(node_id,nonce,seen_at) VALUES(?,?,?)`, nodeID, replayPurposePrefix+nonce, a.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("handshake nonce replay rejected")
	}
	return nil
}

func (a *WatchpostAuthenticator) fresh(ts string) bool {
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return false
	}
	now := a.now()
	return !at.Before(now.Add(-handshakeSkewWindow)) && !at.After(now.Add(handshakeSkewWindow))
}

func (a *WatchpostAuthenticator) pendingValid(exp string) bool {
	at, err := time.Parse(time.RFC3339Nano, exp)
	if err != nil {
		return false
	}
	return at.After(a.now())
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasReplicationCapability(capsJSON string) bool {
	var caps []string
	if err := json.Unmarshal([]byte(capsJSON), &caps); err != nil {
		return false
	}
	for _, c := range caps {
		if c == replicationCapability {
			return true
		}
	}
	return false
}
