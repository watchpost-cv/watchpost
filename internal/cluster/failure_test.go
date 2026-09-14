package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

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

func TestConsumedPairingResultCanBeReissuedAfterLostResponse(t *testing.T) {
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
	receipt, err := pairing.SubmitJoin(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pairing.Decide(ctx, receipt.RequestID, true, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	first, err := pairing.Poll(ctx, receipt.RequestID, receipt.RequestSecret)
	if err != nil {
		t.Fatalf("first poll failed: %v", err)
	}
	if first.Credential == "" {
		t.Fatal("first poll returned no credential")
	}
	// Simulate the response being lost before the joiner persisted it: poll
	// again. The member has never authenticated, so a fresh credential is
	// reissued instead of permanently bricking the pairing.
	second, err := pairing.Poll(ctx, receipt.RequestID, receipt.RequestSecret)
	if err != nil {
		t.Fatalf("re-poll after lost response must recover, got: %v", err)
	}
	if second.Credential == "" || second.Credential == first.Credential {
		t.Fatalf("expected a fresh reissued credential, got %q vs %q", second.Credential, first.Credential)
	}
	// Once the joiner actually uses a credential, the consumed result stays sealed.
	transport := NewTransport(db, identity)
	if _, err = transport.Authenticate(signedIncomingRequest(t, second.Credential, "wp_joiner", "nonce-used", "req-used", "/api/cluster/v1/rpc/status", "cluster.health"), "cluster.health"); err != nil {
		t.Fatalf("reissued credential not accepted: %v", err)
	}
	if _, err = pairing.Poll(ctx, receipt.RequestID, receipt.RequestSecret); err == nil {
		t.Fatal("consumed pairing result reissued after the credential was used")
	}
}

func TestInvitationConcurrentSubmissionMintsSingleJoinRequest(t *testing.T) {
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
	const attempts = 8
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pairing.SubmitJoin(ctx, in)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("single-use invitation produced %d join requests", successes)
	}
	var pending int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cluster_join_requests`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("cluster_join_requests=%d err=%v", pending, err)
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
	r.Header.Set(headerSignature, corecluster.Signature(secret, r.Method, r.URL.RequestURI(), at, nonce, requestID, capability, body))
	return r
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
