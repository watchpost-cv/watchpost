package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func newClusterTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func remoteIdentity(nodeID, installationID, endpoint string) Identity {
	return Identity{
		NodeID: nodeID, InstallationID: installationID, DisplayName: nodeID,
		PublicEndpoint:  endpoint,
		PublicKey:       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		Capabilities:    append([]string(nil), DefaultCapabilities...),
		ProtocolVersion: ProtocolVersion, ProductVersion: "test",
	}
}

func TestInvitationIsSingleUseAndExpires(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	pairing := NewPairingService(db, identity)
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	pairing.now = func() time.Time { return now }
	if _, err := identity.Update(ctx, "host", "https://host.test", nil, "test"); err != nil {
		t.Fatal(err)
	}
	invite, err := pairing.Invite(ctx, audit.Entry{})
	if err != nil {
		t.Fatal(err)
	}
	joiner := remoteIdentity("wp_joiner", "wi_joiner", "https://joiner.test")
	in := JoinSubmission{InvitationToken: invite.Token, Identity: joiner, CredentialForHost: "01234567890123456789012345678901"}
	if _, err = pairing.SubmitJoin(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err = pairing.SubmitJoin(ctx, in); err == nil {
		t.Fatal("single-use invitation accepted twice")
	}

	invite, err = pairing.Invite(ctx, audit.Entry{})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(PairingLifetime + time.Second)
	in.InvitationToken = invite.Token
	if _, err = pairing.SubmitJoin(ctx, in); err == nil {
		t.Fatal("expired invitation accepted")
	}
}

func TestTransportRejectsReplayAndRevocation(t *testing.T) {
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
	request := signedIncomingRequest(t, incoming, "wp_peer", "nonce-1", "req-1", "/api/cluster/v1/rpc/status", "cluster.health")
	if _, err := transport.Authenticate(request, "cluster.health"); err != nil {
		t.Fatal(err)
	}
	request = signedIncomingRequest(t, incoming, "wp_peer", "nonce-1", "req-2", "/api/cluster/v1/rpc/status", "cluster.health")
	if _, err := transport.Authenticate(request, "cluster.health"); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	members := NewMemberService(db)
	if err := members.Revoke(ctx, "wp_peer", audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	request = signedIncomingRequest(t, incoming, "wp_peer", "nonce-2", "req-3", "/api/cluster/v1/rpc/status", "cluster.health")
	if _, err := transport.Authenticate(request, "cluster.health"); err == nil {
		t.Fatal("revoked member authenticated")
	}
}

func TestCredentialRotationPromotesOnlyAfterUse(t *testing.T) {
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
	transport := NewTransport(db, identity)
	if _, err = transport.Authenticate(signedIncomingRequest(t, oldSecret, "wp_peer", "old-before", "req-old", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err != nil {
		t.Fatalf("old credential should remain valid during overlap: %v", err)
	}
	if _, err = transport.Authenticate(signedIncomingRequest(t, newSecret, "wp_peer", "new-use", "req-new", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err != nil {
		t.Fatalf("new credential not accepted: %v", err)
	}
	if _, err = transport.Authenticate(signedIncomingRequest(t, oldSecret, "wp_peer", "old-after", "req-old-after", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err == nil {
		t.Fatal("old credential remained valid after replacement promotion")
	}
}

func TestDuplicateInstallationIdentityRejected(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	pairing := NewPairingService(db, identity)
	if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_one", "wi_shared", "https://one.test"), "outbound-credential-1-abcdefghijklmnopqrstuvwxyz", "inbound-credential-1-abcdefghijklmnopqrstuvwxyz"); err != nil {
		t.Fatal(err)
	}
	if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_two", "wi_shared", "https://two.test"), "outbound-credential-2-abcdefghijklmnopqrstuvwxyz", "inbound-credential-2-abcdefghijklmnopqrstuvwxyz"); err == nil {
		t.Fatal("duplicate installation identity accepted under a second node id")
	}
}

func TestStandaloneAndPartialFanout(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	if _, err := identity.Update(ctx, "local", "https://local.test", nil, "test"); err != nil {
		t.Fatal(err)
	}
	members := NewMemberService(db)
	transport := NewTransport(db, identity)
	distributed := NewDistributedService(db, identity, members, transport)
	report := distributed.ClusterStatus(ctx, "test", "all")
	if report.Partial || len(report.Results) != 1 || !report.Results[0].OK {
		t.Fatalf("standalone status changed: %#v", report)
	}

	pairing := NewPairingService(db, identity)
	if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_peer", "wi_peer", "https://peer.test"), "outbound-credential-abcdefghijklmnopqrstuvwxyz", "inbound-credential-abcdefghijklmnopqrstuvwxyz"); err != nil {
		t.Fatal(err)
	}
	transport.SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("partition")
	})})
	report = distributed.ClusterStatus(ctx, "test", "all")
	if !report.Partial || len(report.Results) != 2 {
		t.Fatalf("partition must be visible as per-node partial failure: %#v", report)
	}
}

func TestRemoveAndRepairMember(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	pairing := NewPairingService(db, identity)
	members := NewMemberService(db)
	remote := remoteIdentity("wp_peer", "wi_peer", "https://peer.test")
	if err := pairing.AcceptRemote(ctx, remote, "outbound-credential-abcdefghijklmnopqrstuvwxyz", "inbound-credential-abcdefghijklmnopqrstuvwxyz"); err != nil {
		t.Fatal(err)
	}
	if err := members.Remove(ctx, remote.NodeID, audit.Entry{}); err == nil {
		t.Fatal("active member removed without disable or revoke")
	}
	if err := members.Revoke(ctx, remote.NodeID, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	if err := members.Remove(ctx, remote.NodeID, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	if err := pairing.AcceptRemote(ctx, remote, "outbound-credential-repair-abcdefghijklmnop", "inbound-credential-repair-abcdefghijklmnop"); err != nil {
		t.Fatalf("re-pair after removal failed: %v", err)
	}
}

func signedIncomingRequest(t *testing.T, secret, nodeID, nonce, requestID, path, capability string) *http.Request {
	t.Helper()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	body := []byte(`{}`)
	r := httptest.NewRequest(http.MethodGet, "https://local.test"+path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set(headerNode, nodeID)
	r.Header.Set(headerTimestamp, at)
	r.Header.Set(headerNonce, nonce)
	r.Header.Set(headerRequestID, requestID)
	r.Header.Set(headerProtocol, "1")
	r.Header.Set(headerCapability, capability)
	r.Header.Set(headerSignature, base64.RawURLEncoding.EncodeToString(signRequest(secret, r.Method, r.URL.RequestURI(), at, nonce, requestID, capability, body)))
	return r
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
