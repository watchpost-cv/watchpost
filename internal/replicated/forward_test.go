package replicated

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// signHandshake builds a signed Gantry RPC handshake for a peer (follower
// perspective), presenting the outbound pairwise secret to the leader.
func signHandshake(t *testing.T, secret, nodeID string) *replication.AuthRequest {
	t.Helper()
	req, err := replication.SignHandshake(secret, raft.ServerID(nodeID), raft.ServerID(nodeID), "", replication.Version,
		replication.Capabilities{ID: raft.ServerID(nodeID), OperationSchemaVersions: []int{1, replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}},
		fmt.Sprintf("nonce-%d", time.Now().UnixNano()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// leaderWithProposeEndpoint builds a real single-node leader whose
// authenticated application-RPC propose endpoint is served over HTTP. The
// authenticate closure verifies the inbound peer via the Watchpost
// authenticator (pairwise credentials + signed handshake + nonce replay).
func leaderWithProposeEndpoint(t *testing.T) (*Controller, *FSM, *httptest.Server) {
	t.Helper()
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{"f": {"A_to_f", "f_to_A"}})
	auth := NewWatchpostAuthenticator(memberA, replication.Version)
	product := openTestDB(t)
	nodeA, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, product, true)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && nodeA.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if nodeA.State() != raft.Leader {
		t.Fatal("A did not become leader")
	}
	fsm := nodeA.FSM().(*FSM)
	adapter := NewAdapter(nodeA, fsm, product, "watchpost")
	ctrl := NewController(adapter)
	ctrl.SetMode(ModeReplicated)
	ctrl.SetReadiness(ReadinessReadyLeader)

	authenticate := func(r *http.Request) (string, error) {
		raw := r.Header.Get("X-Watchpost-Handshake")
		if raw == "" {
			return "", errors.New("missing handshake")
		}
		var req replication.AuthRequest
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			return "", err
		}
		if err := auth.VerifyPeer(r.Context(), req.NodeID, req); err != nil {
			return "", err
		}
		return string(req.NodeID), nil
	}
	srv := httptest.NewServer(ctrl.LeaderProposeHandler(authenticate))
	t.Cleanup(srv.Close)
	return ctrl, fsm, srv
}

// authenticatedForwardClient presents a fresh signed Gantry handshake (peer
// identity + pairwise secret + nonce) for each application RPC call, mirroring
// the production Gantry RPC envelope.
func authenticatedForwardClient(baseURL, peerID, secret string) ForwardClient {
	return func(ctx context.Context, fr ForwardRequest) (*replication.ApplyResult, error) {
		body, err := json.Marshal(fr)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hs, err := replication.SignHandshake(secret, raft.ServerID(peerID), raft.ServerID(peerID), "", replication.Version,
			replication.Capabilities{ID: raft.ServerID(peerID), OperationSchemaVersions: []int{1, replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}},
			fmt.Sprintf("nonce-%d", time.Now().UnixNano()), time.Now())
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(hs)
		req.Header.Set("X-Watchpost-Handshake", string(raw))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("forward rejected (%d): %s", resp.StatusCode, b)
		}
		var ar replication.ApplyResult
		if err := json.Unmarshal(b, &ar); err != nil {
			return nil, err
		}
		return &ar, nil
	}
}

// TestAuthenticatedForwardProposal proves a ready follower's mutation routes
// over the authenticated application RPC to the leader's propose endpoint and
// commits.
func TestAuthenticatedForwardProposal(t *testing.T) {
	_, fsm, srv := leaderWithProposeEndpoint(t)
	fwd := authenticatedForwardClient(srv.URL, "f", "f_to_A")
	fr := ForwardRequest{Kind: KindPostCreate, ObjectID: "p1", OpID: "post-1", Payload: mustJSON(mkPost("host-a", "host"))}
	if _, err := fwd(context.Background(), fr); err != nil {
		t.Fatalf("authenticated forward: %v", err)
	}
	var n int
	if err := fsm.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='p1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("forwarded mutation did not commit: n=%d err=%v", n, err)
	}
}

// TestForwardRejectsUnauthenticated proves the leader propose endpoint refuses
// peers without valid pairwise credentials.
func TestForwardRejectsUnauthenticated(t *testing.T) {
	_, _, srv := leaderWithProposeEndpoint(t)
	fr := ForwardRequest{Kind: KindPostCreate, ObjectID: "p1", OpID: "post-1", Payload: mustJSON(mkPost("host-a", "host"))}
	body, _ := json.Marshal(fr)
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("X-Watchpost-Handshake", "not-a-handshake")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated forward: status %d want 401", resp.StatusCode)
	}
}

// TestForwardAmbiguousRetry proves the durable operation-ID contract at the
// forwarding boundary: retrying the same operation identity with the same
// payload returns the committed result without a second mutation, and the same
// identity with a different payload fails closed.
func TestForwardAmbiguousRetry(t *testing.T) {
	_, fsm, srv := leaderWithProposeEndpoint(t)
	fwd := authenticatedForwardClient(srv.URL, "f", "f_to_A")
	fr := ForwardRequest{Kind: KindPostCreate, ObjectID: "p1", OpID: "post-amb", Payload: mustJSON(mkPost("host-a", "host"))}

	if _, err := fwd(context.Background(), fr); err != nil {
		t.Fatalf("first forward: %v", err)
	}
	if _, err := fwd(context.Background(), fr); err != nil {
		t.Fatalf("ambiguous retry must return the committed result, got error: %v", err)
	}
	var n int
	if err := fsm.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='p1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ambiguous retry mutated twice: n=%d err=%v", n, err)
	}

	altered := ForwardRequest{Kind: KindPostCreate, ObjectID: "p1", OpID: "post-amb", Payload: mustJSON(mkPost("host-b", "host"))}
	if _, err := fwd(context.Background(), altered); err == nil {
		t.Fatal("same operation identity with different payload must fail closed")
	}
	if err := fsm.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='p1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("fail-closed retry mutated state: n=%d", n)
	}
}
