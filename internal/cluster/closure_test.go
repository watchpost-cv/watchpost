package cluster

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"
	"github.com/watchpost-cv/watchpost/internal/audit"
)

// TestPairingRejectPath exercises the join-reject transition: a pending join
// request is rejected, the request can no longer be approved, and the joiner
// cannot complete pairing from the rejected state.
func TestPairingRejectPath(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	pairing := NewPairingService(db, identity)
	if _, err := identity.Update(ctx, "host", "https://host.test", nil, "test"); err != nil {
		t.Fatal(err)
	}
	invite, err := pairing.Invite(ctx, audit.Entry{})
	if err != nil {
		t.Fatal(err)
	}
	joiner := remoteIdentity("wp_joiner", "wi_joiner", "https://joiner.test")
	receipt, err := pairing.SubmitJoin(ctx, JoinSubmission{InvitationToken: invite.Token, Identity: joiner, CredentialForHost: "01234567890123456789012345678901"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID == "" {
		t.Fatal("empty join request id")
	}
	if _, err := pairing.Decide(ctx, receipt.RequestID, false, audit.Entry{}); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, err := pairing.Decide(ctx, receipt.RequestID, true, audit.Entry{}); err == nil {
		t.Fatal("rejected join request was approved")
	}
	var state string
	if err := db.DB.QueryRowContext(ctx, `SELECT state FROM cluster_join_requests WHERE id=?`, receipt.RequestID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "rejected" {
		t.Fatalf("join request state = %q, want rejected", state)
	}
}

// TestTransportRejectsStaleTimestamp proves the production transport path
// rejects a signed request whose timestamp is outside the clock-skew window
// (a replay of an old captured request).
func TestTransportRejectsStaleTimestamp(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	if _, err := identity.Update(ctx, "local", "https://local.test", nil, "test"); err != nil {
		t.Fatal(err)
	}
	pairing := NewPairingService(db, identity)
	const incoming = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_peer", "wi_peer", "https://peer.test"), "outbound-credential-abcdefghijklmnopqrstuvwxyz", incoming); err != nil {
		t.Fatal(err)
	}
	transport := NewTransport(db, identity)
	stale := time.Now().UTC().Add(-10 * time.Minute) // beyond 5-minute ClockSkew
	if _, err := transport.Authenticate(signedIncomingRequestAtTime(t, incoming, "wp_peer", "nonce-stale", "req-stale", "/api/cluster/v1/rpc/status", "cluster.health", stale), "cluster.health"); err == nil {
		t.Fatal("request with stale timestamp was accepted")
	}
	if _, err := transport.Authenticate(signedIncomingRequest(t, incoming, "wp_peer", "nonce-fresh", "req-fresh", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err != nil {
		t.Fatalf("fresh request rejected: %v", err)
	}
}

// TestCredentialRotationPendingSecretExpires proves the previous-credential
// overlap window is bounded: after the pending (rotated-in) secret's expiry
// passes without it being used, it can no longer authenticate while the
// current secret remains valid.
func TestCredentialRotationPendingSecretExpires(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	if _, err := identity.Update(ctx, "local", "https://local.test", nil, "test"); err != nil {
		t.Fatal(err)
	}
	pairing := NewPairingService(db, identity)
	const oldSecret = "old-credential-abcdefghijklmnopqrstuvwxyz0123456789"
	if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_peer", "wi_peer", "https://peer.test"), "outbound-credential-abcdefghijklmnopqrstuvwxyz", oldSecret); err != nil {
		t.Fatal(err)
	}
	members := NewMemberService(db)
	newSecret, err := members.RotateInbound(ctx, "wp_peer", audit.Entry{})
	if err != nil {
		t.Fatal(err)
	}
	if newSecret == "" {
		t.Fatal("empty rotated secret")
	}
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err := db.DB.ExecContext(ctx, `UPDATE cluster_members SET pending_inbound_expires_at=? WHERE node_id=?`, past, "wp_peer"); err != nil {
		t.Fatal(err)
	}
	transport := NewTransport(db, identity)
	if _, err := transport.Authenticate(signedIncomingRequest(t, newSecret, "wp_peer", "nonce-new", "req-new", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err == nil {
		t.Fatal("expired pending secret was accepted")
	}
	if _, err := transport.Authenticate(signedIncomingRequest(t, oldSecret, "wp_peer", "nonce-old", "req-old", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err != nil {
		t.Fatalf("current secret rejected: %v", err)
	}
}

// signedIncomingRequestAtTime builds a signed request with an explicit
// timestamp, mirroring signedIncomingRequest with a caller-supplied time so
// stale-timestamp behaviour is exercised through the real transport path.
func signedIncomingRequestAtTime(t *testing.T, secret, nodeID, nonce, requestID, path, capability string, at time.Time) *http.Request {
	t.Helper()
	timestamp := at.UTC().Format(time.RFC3339Nano)
	body := []byte(`{}`)
	r := httptest.NewRequest(http.MethodGet, "https://local.test"+path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set(headerNode, nodeID)
	r.Header.Set(headerTimestamp, timestamp)
	r.Header.Set(headerNonce, nonce)
	r.Header.Set(headerRequestID, requestID)
	r.Header.Set(headerProtocol, "1")
	r.Header.Set(headerCapability, capability)
	r.Header.Set(headerSignature, corecluster.Signature(secret, r.Method, r.URL.RequestURI(), timestamp, nonce, requestID, capability, body))
	return r
}