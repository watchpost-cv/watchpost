package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/server"
	"github.com/watchpost-cv/watchpost/internal/store"
	_ "modernc.org/sqlite"
)

const memberSchema = `
CREATE TABLE IF NOT EXISTS cluster_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),node_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL DEFAULT '',public_key BLOB NOT NULL,private_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,paired_at TEXT,last_seen_at TEXT,revoked_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_members(node_id TEXT PRIMARY KEY,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL,public_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',inbound_secret_hash BLOB NOT NULL,outbound_secret TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')),created_at TEXT NOT NULL,paired_at TEXT NOT NULL,last_seen_at TEXT,last_latency_ms INTEGER,revoked_at TEXT,credential_version INTEGER NOT NULL DEFAULT 1,pending_inbound_secret_hash BLOB,pending_inbound_expires_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_nonces(node_id TEXT NOT NULL REFERENCES cluster_members(node_id) ON DELETE CASCADE,nonce TEXT NOT NULL,seen_at TEXT NOT NULL,PRIMARY KEY(node_id,nonce));
`

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// seedNode installs the cluster tables + identity + pairwise members on the
// product DB, mirroring the production cluster_identity/cluster_members
// relationship (outbound_secret presented to the peer; peer's secret stored as
// inbound_secret_hash).
func seedNode(t *testing.T, db *sql.DB, nodeID string, peers map[string][2]string) {
	t.Helper()
	mustExec(t, db, memberSchema)
	mustExec(t, db, `INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,created_at) VALUES(1,?,?,?,?,?,?,?)`,
		nodeID, nodeID+"-inst", []byte("key"), []byte("key"), `["health","replication"]`, 1, time.Now().UTC().Format(time.RFC3339Nano))
	for peer, cred := range peers {
		mustExec(t, db, `INSERT INTO cluster_members(node_id,installation_id,public_endpoint,public_key,capabilities_json,protocol_version,inbound_secret_hash,outbound_secret,state,created_at,paired_at,credential_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)`,
			peer, peer+"-inst", "https://"+peer+".example", []byte("key"), `["health","replication"]`, 1, hashSecret(cred[1]), cred[0], "active", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	}
}

func setPublicEndpoint(t *testing.T, db *sql.DB, nodeID, url string) {
	t.Helper()
	mustExec(t, db, `UPDATE cluster_members SET public_endpoint=? WHERE node_id=?`, url, nodeID)
}

type node struct {
	store *store.Store
	srv   *server.Server
	repl  *Replicated
	http  *httptest.Server
}

// newNode builds the production composition exactly as cmd/watchpost serves it:
// store.Open -> server.New -> runtime.New (configured replicated) ->
// server.InstallReplicated -> HTTP.
func newNode(t *testing.T, nodeID string, peers map[string][2]string, bootstrap bool, interval time.Duration) *node {
	t.Helper()
	db, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedNode(t, db.DB, nodeID, peers)
	srv := server.New(config.Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()}, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	var repl *Replicated
	if nodeID != "" {
		repl, err = New(t.Context(), Options{Database: db, NodeID: nodeID, Bootstrap: bootstrap, Transport: srv.ClusterTransport(), SnapshotDir: t.TempDir(), ReadinessInterval: interval})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(repl.Close)
		srv.InstallReplicated(repl.Controller)
	}
	hs := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(hs.Close)
	// The cluster RPC transport and the API client must trust the test TLS
	// server; the HMAC signature + pairwise secret still authenticate each
	// peer request (TLS provides transport confidentiality, relaxed here only
	// because the test uses self-signed certificates).
	srv.ClusterTransport().SetHTTPClient(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}})
	return &node{store: db, srv: srv, repl: repl, http: hs}
}

func waitReadiness(t *testing.T, n *node, want replicated.Readiness) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, rd := n.repl.Controller.State()
		if rd == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mode, rd := n.repl.Controller.State()
	t.Fatalf("readiness=%s want %s (mode=%s)", rd, want, mode)
}

func httpPost(t *testing.T, client *http.Client, baseURL string, body any) (int, []byte) {
	t.Helper()
	do := func(method, path string, payload any, cookie *http.Cookie, csrf string) (*http.Response, []byte) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, baseURL+path, rd)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-Watchpost-CSRF", csrf)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	_, _ = do("POST", "/api/v1/setup", map[string]string{"username": "admin", "email": "admin@example.com", "password": "1234567"}, nil, "")
	login, lb := do("POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(lb, &session)
	resp, rb := do("POST", "/api/v1/posts", body, cookie, session.CSRF)
	return resp.StatusCode, rb
}

func countPosts(t *testing.T, n *node, id string) int {
	t.Helper()
	var c int
	if err := n.store.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id=?`, id).Scan(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestStandaloneExecutable proves the ordinary construction (no runtime) serves
// local mutations without any raft cluster.
func TestStandaloneExecutable(t *testing.T) {
	n := newNode(t, "", nil, false, 0)
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "solo", "name": "Solo", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("standalone HTTP post: %d", code)
	}
	if countPosts(t, n, "solo") != 1 {
		t.Fatal("standalone local mutation not persisted")
	}
}

// TestReplicatedLeaderExecutable proves a configured replicated single-node
// leader: the real production composition reaches ready-leader and HTTP
// mutations commit through raft.
func TestReplicatedLeaderExecutable(t *testing.T) {
	n := newNode(t, "A", nil, true, 0)
	waitReadiness(t, n, replicated.ReadinessReadyLeader)
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("leader HTTP post: %d", code)
	}
	if countPosts(t, n, "host-a") != 1 {
		t.Fatal("leader replicated mutation not committed")
	}
}

// TestReplicatedFollowerForwarding proves a ready follower's HTTP mutation is
// forwarded over the authenticated Gantry cluster RPC to the leader's proposal
// endpoint and converges on both nodes.
func TestReplicatedFollowerForwarding(t *testing.T) {
	const aToB, bToA = "A_to_B", "B_to_A"
	a := newNode(t, "A", map[string][2]string{"B": {aToB, bToA}}, true, 0)
	b := newNode(t, "B", map[string][2]string{"A": {bToA, aToB}}, false, 0)
	waitReadiness(t, a, replicated.ReadinessReadyLeader)
	if err := a.repl.Node.AddVoter("B", b.repl.Node.Address()); err != nil {
		t.Fatalf("join B: %v", err)
	}
	setPublicEndpoint(t, a.store.DB, "B", b.http.URL)
	setPublicEndpoint(t, b.store.DB, "A", a.http.URL)
	waitReadiness(t, b, replicated.ReadinessReadyFollower)

	code, rb := httpPost(t, b.http.Client(), b.http.URL, map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("follower HTTP post: %d %s", code, rb)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1) {
		time.Sleep(20 * time.Millisecond)
	}
	if countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1 {
		t.Fatalf("forwarded mutation did not converge: A=%d B=%d", countPosts(t, a, "host-a"), countPosts(t, b, "host-a"))
	}
}

// TestReplicatedStartupReject proves HTTP mutations are rejected before the
// runtime readiness lifecycle promotes the node.
func TestReplicatedStartupReject(t *testing.T) {
	n := newNode(t, "A", nil, true, time.Minute)
	mode, rd := n.repl.Controller.State()
	if mode != replicated.ModeReplicated || rd != replicated.ReadinessStarting {
		t.Fatalf("state=%s/%s want replicated/starting", mode, rd)
	}
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "early", "name": "Early", "kind": "host", "labels": map[string]string{}})
	if code == http.StatusCreated {
		t.Fatal("HTTP mutation must be rejected at readiness starting")
	}
	if countPosts(t, n, "early") != 0 {
		t.Fatal("startup-rejected mutation mutated the DB")
	}
}

// TestReplicatedNoLeaderReject proves a configured replicated node with no
// usable leader rejects HTTP mutations without any local fallback.
func TestReplicatedNoLeaderReject(t *testing.T) {
	n := newNode(t, "X", nil, false, 0)
	waitReadiness(t, n, replicated.ReadinessNoLeader)
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "late", "name": "Late", "kind": "host", "labels": map[string]string{}})
	if code == http.StatusCreated {
		t.Fatal("no-leader HTTP mutation must fail")
	}
	if countPosts(t, n, "late") != 0 {
		t.Fatal("no-leader node fell back to local SQL")
	}
}

// TestReplicatedShutdownDrain proves shutdown drives readiness to
// shutting-down (rejecting new mutations) and cleanly shuts down the node.
func TestReplicatedShutdownDrain(t *testing.T) {
	n := newNode(t, "A", nil, true, 0)
	waitReadiness(t, n, replicated.ReadinessReadyLeader)
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("pre-shutdown post: %d", code)
	}
	n.repl.Close()
	_, rd := n.repl.Controller.State()
	if rd != replicated.ReadinessShuttingDown {
		t.Fatalf("readiness=%s want shutting-down after Close", rd)
	}
	code, _ = httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "after", "name": "After", "kind": "host", "labels": map[string]string{}})
	if code == http.StatusCreated {
		t.Fatal("HTTP mutation must be rejected during shutdown")
	}
	if countPosts(t, n, "after") != 0 {
		t.Fatal("shutdown mutation mutated the DB")
	}
	if n.repl.Node.State() != raft.Shutdown {
		t.Fatalf("node state=%s want shutdown", n.repl.Node.State())
	}
}

var _ = context.Background
