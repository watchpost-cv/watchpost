package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/store"
	_ "modernc.org/sqlite"
)

// replicatedMemberSchema is a minimal cluster_identity/cluster_members/
// cluster_nonces fixture for the production authenticator.
const replicatedMemberSchema = `
CREATE TABLE IF NOT EXISTS cluster_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),node_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL DEFAULT '',public_key BLOB NOT NULL,private_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,paired_at TEXT,last_seen_at TEXT,revoked_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_members(node_id TEXT PRIMARY KEY,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL,public_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',inbound_secret_hash BLOB NOT NULL,outbound_secret TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')),created_at TEXT NOT NULL,paired_at TEXT NOT NULL,last_seen_at TEXT,last_latency_ms INTEGER,revoked_at TEXT,credential_version INTEGER NOT NULL DEFAULT 1,pending_inbound_secret_hash BLOB,pending_inbound_expires_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_nonces(node_id TEXT NOT NULL REFERENCES cluster_members(node_id) ON DELETE CASCADE,nonce TEXT NOT NULL,seen_at TEXT NOT NULL,PRIMARY KEY(node_id,nonce));
`

// newReplicatedLeader builds a real production-stack leader Controller over the
// server's product database and installs it into the server.
func newReplicatedServer(t *testing.T, ready replicated.Readiness, install bool) (*Server, *store.Store, *replicated.Controller) {
	t.Helper()
	database, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	srv := New(config.Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()}, "test-version", slog.New(slog.NewTextHandler(io.Discard, nil)), database)

	if !install {
		return srv, database, nil
	}

	// Membership fixture for the local leader node.
	member, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "member.db")+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { member.Close() })
	if _, err := member.Exec(replicatedMemberSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := member.Exec(`INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,created_at) VALUES(1,'leader','leader-inst',?,?,'["health","replication"]',1,?)`, []byte("k"), []byte("k"), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	// Production stack: authenticator -> TLS-less (test) transport -> raft node
	// over the server's product DB -> adapter -> controller.
	auth := replicated.NewWatchpostAuthenticator(member, replication.Version)
	nt, err := replication.NewNetTransport(replication.NetTransportOptions{
		ID: "leader", Address: "127.0.0.1:0", Authenticator: auth, Membership: auth, PeerCredentials: auth,
		Protocol:        replication.Version,
		Capabilities:    replication.Capabilities{ID: "leader", OperationSchemaVersions: []int{1, replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}},
		RevalidateEvery: time.Hour, InsecureAllowPlaintext: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nt.Close() })
	fsm, err := replicated.NewFSM(database.DB)
	if err != nil {
		t.Fatal(err)
	}
	snaps, err := raft.NewFileSnapshotStore(t.TempDir(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	node, err := replication.NewNode(replication.NodeOptions{
		ID: "leader", Address: nt.LocalAddr(), Transport: nt,
		LogStore: raft.NewInmemStore(), StableStore: raft.NewInmemStore(), SnapshotStore: snaps,
		FSM: fsm, Bootstrap: true, CapabilitySource: auth,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Shutdown() })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && node.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if node.State() != raft.Leader {
		t.Fatal("replicated leader node did not become leader")
	}

	adapter := replicated.NewAdapter(node, fsm, database.DB, "watchpost")
	ctrl := replicated.NewController(adapter)
	ctrl.SetMode(replicated.ModeReplicated)
	ctrl.SetReadiness(ready)
	srv.InstallReplicated(ctrl)
	return srv, database, ctrl
}

func authedPost(t *testing.T, handler http.Handler, body any) int {
	t.Helper()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"username": "admin", "email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	return apiRequest(t, handler, "POST", "/api/v1/posts", body, cookie, session.CSRF).Code
}

// TestLiveHTTPLeaderMutation proves the actual HTTP path routes a post create
// through the replicated authority to Raft and converges on the product DB.
func TestLiveHTTPLeaderMutation(t *testing.T) {
	srv, database, _ := newReplicatedServer(t, replicated.ReadinessReadyLeader, true)
	code := authedPost(t, srv.Handler(), map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("leader HTTP post: %d", code)
	}
	var n int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='host-a'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("replicated HTTP mutation did not commit: n=%d err=%v", n, err)
	}
}

// TestLiveHTTPRejection proves non-ready replicated readiness rejects HTTP
// mutations without local fallback.
func TestLiveHTTPRejection(t *testing.T) {
	for _, rd := range []replicated.Readiness{replicated.ReadinessStarting, replicated.ReadinessLearner, replicated.ReadinessNoLeader, replicated.ReadinessUnhealthy, replicated.ReadinessShuttingDown} {
		t.Run(rd.String(), func(t *testing.T) {
			srv, database, _ := newReplicatedServer(t, rd, true)
			code := authedPost(t, srv.Handler(), map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
			if code == http.StatusCreated {
				t.Fatal("HTTP mutation must be rejected at non-ready readiness")
			}
			var n int
			if err := database.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='host-a'`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("rejected HTTP mutation mutated the DB: n=%d", n)
			}
		})
	}
}

// TestLiveHTTPNoLocalFallback proves the central invariant at the HTTP
// boundary: when a configured replicated node loses readiness, HTTP mutations
// fail and existing replicated state is unchanged.
func TestLiveHTTPNoLocalFallback(t *testing.T) {
	srv, database, ctrl := newReplicatedServer(t, replicated.ReadinessReadyLeader, true)
	if code := authedPost(t, srv.Handler(), map[string]any{"id": "keep", "name": "Keep", "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
		t.Fatalf("initial HTTP post: %d", code)
	}
	ctrl.SetReadiness(replicated.ReadinessNoLeader)
	if code := authedPost(t, srv.Handler(), map[string]any{"id": "after", "name": "After", "kind": "host", "labels": map[string]string{}}); code == http.StatusCreated {
		t.Fatal("HTTP mutation must fail when replication is unavailable")
	}
	var n int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='after'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("replicated node fell back to local SQL: n=%d", n)
	}
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='keep'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("existing replicated state changed: n=%d", n)
	}
}

// TestLiveHTTPStandalone proves a server without the authority uses the
// existing local path.
func TestLiveHTTPStandalone(t *testing.T) {
	srv, database, _ := newReplicatedServer(t, 0, false)
	if code := authedPost(t, srv.Handler(), map[string]any{"id": "solo", "name": "Solo", "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
		t.Fatalf("standalone HTTP post: %d", code)
	}
	var n int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='solo'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("standalone local mutation failed: n=%d", n)
	}
}

var _ = context.Background
var _ = httptest.NewRequest
