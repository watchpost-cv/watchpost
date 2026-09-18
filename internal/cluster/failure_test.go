package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestStaleOutboundJoinCannotOverwriteCredentials reproduces the campaign-3
// finding: after revoke/remove + re-pair, a stale approved outbound join for
// the same remote must not be collectable, because collecting it would
// overwrite the active membership credential with a stale generation (the
// peer then rejects the inviter with 401). Only the most recent outbound join
// for a remote URL may transition credentials.
// TestStaleOutboundJoinCannotOverwriteCredentials reproduces the campaign-3
// finding: after revoke/remove + re-pair, a stale outbound join for the same
// remote must never overwrite the active membership credential with a stale
// generation (which would make the inviter reject the peer with 401).
//
// The intended state-machine invariant: at most one outbound join per remote
// may be capable of changing active membership credentials (the newest
// pending generation). An approved (already-collected) join is a harmless
// no-op, and a stale pending join is rejected as superseded.
func TestStaleOutboundJoinCannotOverwriteCredentials(t *testing.T) {
	ctx := context.Background()
	db := newClusterTestStore(t)
	identity := NewIdentityService(db)
	pairing := NewPairingService(db, identity)
	const remote = "https://watchpost.test.sslip.io"
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	pairing.now = func() time.Time { return now }
	badClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unreachable")
	})}
	insert := func(id, state string, at time.Time) {
		t.Helper()
		if _, err := db.DB.ExecContext(ctx, `INSERT INTO cluster_outbound_joins(id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id, remote, "req_"+id, "secret-"+id, "cred-"+id+"-abcdefghijklmnopqrstuvwxyz", state, at.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}

	// Initial pairing: a single approved (already-collected) join.
	oldID := "out_oldgeneration0000"
	insert(oldID, "approved", now)
	// Re-collecting an approved join is a harmless no-op (returns the record,
	// does not fetch or rewrite membership credentials).
	if _, err := pairing.CollectOutbound(ctx, oldID, badClient); err != nil {
		t.Fatalf("approved join re-collect should be a no-op, got: %v", err)
	}

	// Re-pair: a newer pending join appears for the same remote.
	newID := "out_newgeneration1111"
	insert(newID, "pending", now.Add(time.Second))
	// The stale approved join is now rejected as superseded (it cannot
	// overwrite the current generation's membership credentials).
	if _, err := pairing.CollectOutbound(ctx, oldID, badClient); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("stale approved join not rejected as superseded: %v", err)
	}
	// The current pending join passes the generation check (fetch fails, not supersede).
	if _, err := pairing.CollectOutbound(ctx, newID, badClient); err == nil || strings.Contains(err.Error(), "superseded") {
		t.Fatalf("current outbound join wrongly superseded: %v", err)
	}

	// A stale PENDING generation (never collected) must be rejected so it
	// cannot overwrite credentials with an old localCredential.
	stalePendingID := "out_stalepending3333"
	insert(stalePendingID, "pending", now)
	_ = stalePendingID // not the newest for remote, and pending -> rejected
	if _, err := pairing.CollectOutbound(ctx, stalePendingID, nil); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("stale pending outbound join not rejected as superseded: %v", err)
	}

	// Repeated re-pair: every older join stays non-overwriting; only the newest
	// pending join is collectable.
	thirdID := "out_thirdgeneration2222"
	insert(thirdID, "pending", now.Add(2*time.Second))
	if _, err := pairing.CollectOutbound(ctx, newID, nil); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("superseded pending join %s not rejected: %v", newID, err)
	}
	if _, err := pairing.CollectOutbound(ctx, thirdID, badClient); err == nil || strings.Contains(err.Error(), "superseded") {
		t.Fatalf("latest pending join wrongly superseded: %v", err)
	}

	// Simulated restart: the invariant is persisted (a newer join still exists
	// in the reopened data directory).
	dir := t.TempDir()
	dbr, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	insertInto := func(t *testing.T, db *store.Store, id, state string, at time.Time) {
		t.Helper()
		if _, err := db.DB.ExecContext(ctx, `INSERT INTO cluster_outbound_joins(id,remote_url,request_id,request_secret,local_inbound_credential,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id, remote, "req_"+id, "secret-"+id, "cred-"+id+"-abcdefghijklmnopqrstuvwxyz", state, at.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	insertInto(t, dbr, oldID, "approved", now)
	insertInto(t, dbr, "out_restartnew4444", "pending", now.Add(time.Second))
	dbr.Close()
	db2, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	pairing2 := NewPairingService(db2, identity)
	if _, err := pairing2.CollectOutbound(ctx, oldID, nil); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("after restart stale approved join not rejected as superseded: %v", err)
	}
	if _, err := pairing2.CollectOutbound(ctx, "out_restartnew4444", badClient); err == nil || strings.Contains(err.Error(), "superseded") {
		t.Fatalf("after restart current join wrongly superseded: %v", err)
	}
}
