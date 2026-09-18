package cluster

import (
	"context"
	"strings"
	"testing"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

	"github.com/watchpost-cv/watchpost/internal/audit"
)

func TestWatchpostClusterTransportPolicy(t *testing.T) {
	ctx := context.Background()

	// Default: HTTP endpoints are rejected everywhere.
	{
		db := newClusterTestStore(t)
		identity := NewIdentityService(db)
		if _, err := identity.Update(ctx, "node", "http://node.test", nil, "test"); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http public endpoint accepted by default (err=%v)", err)
		}
		pairing := NewPairingService(db, identity)
		if _, err := identity.Update(ctx, "host", "https://host.test", nil, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := pairing.BeginOutbound(ctx, "http://remote.test", "token", nil); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http remote join accepted by default (err=%v)", err)
		}
		transport := NewTransport(db, identity)
		if err := pairing.AcceptRemote(ctx, remoteIdentity("wp_peer", "wi_peer", "http://peer.test"), "outbound-credential-abcdefghijklmnopqrstuvwxyz", "inbound-credential-abcdefghijklmnopqrstuvwxyz"); err != nil {
			t.Fatal(err)
		}
		if _, err := transport.Do(ctx, "wp_peer", "GET", "/api/cluster/v1/rpc/status", "cluster.health", nil); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http peer RPC accepted by default (err=%v)", err)
		}
		// A default SubmitJoin rejects an HTTP-advertised joiner.
		if _, err := identity.Update(ctx, "host2", "https://host2.test", nil, "test"); err != nil {
			t.Fatal(err)
		}
		invite, err := NewPairingService(db, identity).Invite(ctx, audit.Entry{})
		if err != nil {
			t.Fatal(err)
		}
		joiner := remoteIdentity("wp_joiner", "wi_joiner", "http://joiner.test")
		in := JoinSubmission{InvitationToken: invite.Token, Identity: joiner, CredentialForHost: "01234567890123456789012345678901"}
		if _, err := pairing.SubmitJoin(ctx, in); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("http-advertised join accepted by default (err=%v)", err)
		}
	}

	// Explicit plaintext mode: HTTP endpoints are accepted; the join path works.
	{
		db := newClusterTestStore(t)
		identity := NewIdentityService(db)
		identity.SetInsecurePlaintext(true)
		if _, err := identity.Update(ctx, "node", "http://node.test", nil, "test"); err != nil {
			t.Fatalf("http public endpoint rejected in plaintext mode: %v", err)
		}
		if _, err := identity.Update(ctx, "host", "http://host.test", nil, "test"); err != nil {
			t.Fatal(err)
		}
		pairing := NewPairingService(db, identity)
		pairing.SetInsecurePlaintext(true)
		if _, err := pairing.BeginOutbound(ctx, "http://remote.test", "token", nil); err == nil || strings.Contains(err.Error(), "https") {
			t.Fatalf("plaintext remote join unexpectedly blocked by guard (err=%v)", err)
		}
		invite, err := pairing.Invite(ctx, audit.Entry{})
		if err != nil {
			t.Fatal(err)
		}
		joiner := remoteIdentity("wp_joiner", "wi_joiner", "http://joiner.test")
		in := JoinSubmission{InvitationToken: invite.Token, Identity: joiner, CredentialForHost: "01234567890123456789012345678901"}
		receipt, err := pairing.SubmitJoin(ctx, in)
		if err != nil {
			t.Fatalf("plaintext join rejected: %v", err)
		}
		if _, err := pairing.Decide(ctx, receipt.RequestID, true, audit.Entry{}); err != nil {
			t.Fatalf("plaintext approve failed: %v", err)
		}
		result, err := pairing.Poll(ctx, receipt.RequestID, receipt.RequestSecret)
		if err != nil {
			t.Fatalf("plaintext poll failed: %v", err)
		}
		if result.State != "approved" || result.Remote == nil || result.Credential == "" {
			t.Fatalf("plaintext poll result=%+v", result)
		}
		transport := NewTransport(db, identity)
		transport.SetInsecurePlaintext(true)
		if _, err := transport.Do(ctx, "wp_joiner", "GET", "/api/cluster/v1/rpc/status", "cluster.health", nil); err == nil || strings.Contains(err.Error(), "https") {
			t.Fatalf("plaintext peer RPC unexpectedly blocked by guard (err=%v)", err)
		}
		_ = corecluster.ProtocolVersion
	}
}