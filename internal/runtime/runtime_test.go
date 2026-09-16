package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

// testCA is a shared cluster certificate authority for mutual-TLS replication.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "watchpost-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) nodeTLS(t *testing.T, name string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	// The transport uses one config for client and server roles: the server
	// requires + verifies peer certificates against the cluster CA (ClientAuth),
	// while the client skips hostname verification because peer identity is
	// bound by the mutual Gantry handshake over the encrypted channel.
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

type node struct {
	store     *store.Store
	srv       *server.Server
	repl      *Replicated
	http      *httptest.Server
	closeOnce sync.Once
}

func (n *node) close() {
	n.closeOnce.Do(func() {
		if n.repl != nil {
			n.repl.Close()
		}
		n.http.Close()
		_ = n.store.Close()
	})
}

// newNode builds the production composition exactly as cmd/watchpost serves it:
// store.Open(dataDir) -> server.New -> runtime.New (configured replicated, over
// the durable <dataDir>/replication raft state and mutual-TLS transport) ->
// server.InstallReplicated -> HTTP. seed=true installs the cluster identity and
// member rows (first start only).
func newNode(t *testing.T, ca *testCA, dataDir, nodeID string, peers map[string][2]string, bootstrap bool, interval time.Duration, seed bool, address string) *node {
	t.Helper()
	db, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if seed {
		seedNode(t, db.DB, nodeID, peers)
	}
	srv := server.New(config.Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()}, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	var repl *Replicated
	if nodeID != "" {
		repl, err = New(t.Context(), Options{Database: db, DataDir: dataDir, NodeID: nodeID, Bootstrap: bootstrap, Address: address, TLSConfig: ca.nodeTLS(t, nodeID), Transport: srv.ClusterTransport(), ReadinessInterval: interval})
		if err != nil {
			t.Fatal(err)
		}
		srv.InstallReplicated(repl.Controller)
	}
	hs := httptest.NewTLSServer(srv.Handler())
	srv.ClusterTransport().SetHTTPClient(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}})
	n := &node{store: db, srv: srv, repl: repl, http: hs}
	t.Cleanup(n.close)
	return n
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

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestStandaloneExecutable proves the ordinary construction (no runtime) serves
// local mutations without any raft cluster.
func TestStandaloneExecutable(t *testing.T) {
	n := newNode(t, nil, t.TempDir(), "", nil, false, 0, false, "")
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "solo", "name": "Solo", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("standalone HTTP post: %d", code)
	}
	if countPosts(t, n, "solo") != 1 {
		t.Fatal("standalone local mutation not persisted")
	}
}

// TestReplicatedLeaderExecutable proves a configured replicated single-node
// leader: the real production composition (durable raft + mutual TLS) reaches
// ready-leader and HTTP mutations commit through raft.
func TestReplicatedLeaderExecutable(t *testing.T) {
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, 0, true, "")
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
// forwarded over the authenticated Gantry cluster RPC (HTTPS) to the leader's
// proposal endpoint over mutual-TLS raft replication and converges on both.
func TestReplicatedFollowerForwarding(t *testing.T) {
	ca := newTestCA(t)
	const aToB, bToA = "A_to_B", "B_to_A"
	a := newNode(t, ca, t.TempDir(), "A", map[string][2]string{"B": {aToB, bToA}}, true, 0, true, freeAddr(t))
	b := newNode(t, ca, t.TempDir(), "B", map[string][2]string{"A": {bToA, aToB}}, false, 0, true, freeAddr(t))
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
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, time.Minute, true, "")
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
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "X", nil, false, 0, true, "")
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
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, 0, true, "")
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

// TestReplicatedRequiresTLS proves production composition fails closed unless
// the replication channel is encrypted or plaintext is explicitly opted in.
func TestReplicatedRequiresTLS(t *testing.T) {
	db, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedNode(t, db.DB, "A", nil)
	srv := server.New(config.Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()}, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	if _, err := New(t.Context(), Options{Database: db, DataDir: t.TempDir(), NodeID: "A", Bootstrap: true, Transport: srv.ClusterTransport()}); err == nil {
		t.Fatal("production composition must fail closed without replication TLS")
	}
	// Explicit plaintext opt-in is the only way to disable encryption.
	repl, err := New(t.Context(), Options{Database: db, DataDir: t.TempDir(), NodeID: "A", Bootstrap: true, InsecurePlaintext: true, Transport: srv.ClusterTransport()})
	if err != nil {
		t.Fatalf("explicit plaintext opt-in: %v", err)
	}
	repl.Close()
}

// TestReplicatedDurableRestart exercises the CP7D-3 recovery wall through the
// production runtime composition: snapshot + trailing log + durable raft state,
// full shutdown, then reconstruction over the SAME data directory.
func TestReplicatedDurableRestart(t *testing.T) {
	ca := newTestCA(t)
	dataDir := t.TempDir()
	addr := freeAddr(t)

	// Run 1: bootstrap leader, commit through S then P, add node-local history.
	n1 := newNode(t, ca, dataDir, "A", nil, true, 0, true, addr)
	waitReadiness(t, n1, replicated.ReadinessReadyLeader)
	for _, p := range [][2]string{{"host-a", "Host A"}, {"host-b", "Host B"}} {
		code, _ := httpPost(t, n1.http.Client(), n1.http.URL, map[string]any{"id": p[0], "name": p[1], "kind": "host", "labels": map[string]string{}})
		if code != http.StatusCreated {
			t.Fatalf("run1 post %s: %d", p[0], code)
		}
	}
	// Node-local history referencing a replicated definition.
	mustExec(t, n1.store.DB, `INSERT INTO changes(post_id,kind,occurred_at,actor,summary) VALUES('host-a','test',?,'t','node-local history')`, time.Now().UTC().Format(time.RFC3339Nano))
	// Force a raft snapshot at S, then commit further through P > S.
	if err := n1.repl.Node.Snapshot(); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if code, _ := httpPost(t, n1.http.Client(), n1.http.URL, map[string]any{"id": "host-c", "name": "Host C", "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
		t.Fatalf("run1 post host-c: %d", code)
	}
	n1.close() // close raft + transport + sqlite entirely

	// Run 2: reconstruct a NEW runtime over the SAME data directory (restored
	// durable raft log/stable/snapshot + persisted SQLite). No re-bootstrap.
	n2 := newNode(t, ca, dataDir, "A", nil, false, 0, false, addr)
	waitReadiness(t, n2, replicated.ReadinessReadyLeader)

	for _, id := range []string{"host-a", "host-b", "host-c"} {
		if countPosts(t, n2, id) != 1 {
			t.Fatalf("definition through P lost after restart: %s", id)
		}
	}
	var rev string
	if err := n2.store.DB.QueryRow(`SELECT v FROM _replicated_meta WHERE k='graph_revision'`).Scan(&rev); err != nil {
		t.Fatalf("graph revision missing after restart: %v", err)
	}
	var ch int
	if err := n2.store.DB.QueryRow(`SELECT COUNT(*) FROM changes WHERE post_id='host-a'`).Scan(&ch); err != nil || ch != 1 {
		t.Fatalf("node-local history lost after restart: %d %v", ch, err)
	}
	applied, _ := n2.repl.Node.AppliedIndex()
	if applied == 0 {
		t.Fatal("raft applied index did not survive restart (durable log/stable state not restored)")
	}
	// A new replicated mutation succeeds after restart.
	code, _ := httpPost(t, n2.http.Client(), n2.http.URL, map[string]any{"id": "host-d", "name": "Host D", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("post-restart mutation: %d", code)
	}
	if countPosts(t, n2, "host-d") != 1 {
		t.Fatal("post-restart mutation not committed")
	}
}

// TestReplicatedShutdownRestartLoop proves repeated start/write/shutdown/
// restart cycles reopen the durable stores cleanly without leaks.
func TestReplicatedShutdownRestartLoop(t *testing.T) {
	ca := newTestCA(t)
	dataDir := t.TempDir()
	addr := freeAddr(t)
	for i := 0; i < 3; i++ {
		n := newNode(t, ca, dataDir, "A", nil, i == 0, 0, i == 0, addr)
		waitReadiness(t, n, replicated.ReadinessReadyLeader)
		id := "loop-" + string(rune('a'+i))
		if code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": id, "name": id, "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
			t.Fatalf("loop %d post: %d", i, code)
		}
		n.close()
	}
	// Final reopen: all three mutations durable.
	fin := newNode(t, ca, dataDir, "A", nil, false, 0, false, addr)
	defer fin.close()
	waitReadiness(t, fin, replicated.ReadinessReadyLeader)
	for _, id := range []string{"loop-a", "loop-b", "loop-c"} {
		if countPosts(t, fin, id) != 1 {
			t.Fatalf("loop mutation lost: %s", id)
		}
	}
}

var _ = context.Background
