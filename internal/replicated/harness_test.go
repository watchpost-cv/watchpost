package replicated

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
	_ "modernc.org/sqlite"
)

const testSchema = `
PRAGMA foreign_keys=ON;
CREATE TABLE posts(id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, address TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', labels_json TEXT NOT NULL DEFAULT '{}', maintenance INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE post_dependencies(post_id TEXT NOT NULL REFERENCES posts(id), depends_on_id TEXT NOT NULL REFERENCES posts(id), PRIMARY KEY(post_id,depends_on_id), CHECK(post_id<>depends_on_id));
CREATE TABLE rules(id TEXT PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), signal TEXT NOT NULL, operator TEXT NOT NULL, threshold REAL NOT NULL, duration_seconds INTEGER NOT NULL DEFAULT 0, recovery_threshold REAL, missing_policy TEXT NOT NULL DEFAULT 'unknown', severity TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE users(id INTEGER PRIMARY KEY);
CREATE TABLE incidents(id INTEGER PRIMARY KEY);
CREATE TABLE alerts(id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES rules(id), post_id TEXT NOT NULL REFERENCES posts(id), state TEXT NOT NULL, severity TEXT NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL, acknowledged_at TEXT, resolved_at TEXT, value REAL);
CREATE TABLE observations(id INTEGER PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), collector_id TEXT NOT NULL REFERENCES collector_keys(id), observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL, sequence INTEGER NOT NULL, signal TEXT NOT NULL, value REAL, unit TEXT NOT NULL, quality TEXT NOT NULL, labels_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE logs(id INTEGER PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), source TEXT NOT NULL, observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, fields_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE changes(id INTEGER PRIMARY KEY, post_id TEXT REFERENCES posts(id), kind TEXT NOT NULL, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, summary TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE conversations(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), post_id TEXT REFERENCES posts(id), incident_id INTEGER REFERENCES incidents(id), created_at TEXT NOT NULL);
CREATE TABLE conversation_messages(id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations(id), message TEXT NOT NULL);
CREATE TABLE action_requests(id INTEGER PRIMARY KEY, type TEXT NOT NULL, post_id TEXT REFERENCES posts(id), parameters_json TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE collector_keys(id TEXT PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), secret_hash BLOB NOT NULL, revoked_at TEXT, last_sequence INTEGER NOT NULL DEFAULT 0);
CREATE TABLE collector_pairing_tokens(token_hash BLOB PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE device_profiles(id TEXT PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), kind TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE device_profile_oids(profile_id TEXT NOT NULL REFERENCES device_profiles(id), oid TEXT NOT NULL);
CREATE TABLE notification_deliveries(id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id), destination TEXT NOT NULL);
CREATE TABLE incident_alerts(alert_id INTEGER NOT NULL REFERENCES alerts(id), incident_id INTEGER NOT NULL REFERENCES incidents(id));
`

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repl.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(testSchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type harness struct {
	t        *testing.T
	nodes    []*replication.Node
	fsms     []*FSM
	adapters []*Adapter
	dbs      []*sql.DB
	fabric   *replication.Fabric
}

func newHarness(t *testing.T, n int) *harness {
	t.Helper()
	h := &harness{t: t, fabric: replication.NewFabric()}
	t.Cleanup(func() {
		for _, node := range h.nodes {
			_ = node.Shutdown()
		}
	})
	for i := 0; i < n; i++ {
		id := raft.ServerID(fmt.Sprintf("n%d", i+1))
		addr := raft.ServerAddress("node-" + string(id))
		db := openTestDB(t)
		fsm, err := NewFSM(db)
		if err != nil {
			t.Fatal(err)
		}
		nt := replication.NewNodeTransport(id, addr, h.fabric)
		snaps, err := raft.NewFileSnapshotStore(filepath.Join(t.TempDir(), "snap"), 3, nil)
		if err != nil {
			t.Fatal(err)
		}
		node, err := replication.NewNode(replication.NodeOptions{
			ID: id, Address: addr, Transport: nt,
			LogStore: raft.NewInmemStore(), StableStore: raft.NewInmemStore(), SnapshotStore: snaps,
			Fabric: h.fabric, FSM: fsm, Bootstrap: i == 0,
			HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
			CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
			ProposeTimeout: 3 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		h.fabric.RegisterNode(node)
		h.nodes = append(h.nodes, node)
		h.fsms = append(h.fsms, fsm)
		h.adapters = append(h.adapters, NewAdapter(node, fsm, db, "watchpost"))
		h.dbs = append(h.dbs, db)
	}
	for i := 1; i < n; i++ {
		h.joinVoter(h.nodes[i].ID(), h.nodes[i].Address())
	}
	h.waitAllLeaderKnown()
	return h
}

func (h *harness) joinVoter(id raft.ServerID, addr raft.ServerAddress) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		leader := h.leaderNode()
		if leader == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err := leader.AddVoter(id, addr); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("join voter %s timed out", id)
}

func (h *harness) leaderNode() *replication.Node {
	for _, n := range h.nodes {
		if n.State() == raft.Leader {
			return n
		}
	}
	return nil
}

func (h *harness) leaderIndex() int {
	for i, n := range h.nodes {
		if n.State() == raft.Leader {
			return i
		}
	}
	h.t.Fatal("no leader")
	return -1
}

func (h *harness) waitAllLeaderKnown() {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var known raft.ServerID
		all := true
		for _, n := range h.nodes {
			_, lid := n.Leader()
			if lid == "" {
				all = false
				break
			}
			if known == "" {
				known = lid
			} else if lid != known {
				all = false
				break
			}
		}
		if all && known != "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("nodes did not agree on a leader")
}

func (h *harness) leader() *Adapter { return h.adapters[h.leaderIndex()] }

// waitConverge blocks until every node has applied through the leader's applied
// index (followers apply asynchronously after receiving the log).
func (h *harness) waitConverge() {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		la, _ := h.nodes[h.leaderIndex()].AppliedIndex()
		all := true
		for _, n := range h.nodes {
			da, _ := n.AppliedIndex()
			if da < la {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("nodes did not converge to the leader's applied index")
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func mkPost(name, kind string) PostPayload {
	return PostPayload{Name: name, Kind: kind, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
}

// TestReplicatedDefinitionsConverge proves the six semantic operations
// replicate identically across three nodes with a shared dependency-graph
// revision.
func TestReplicatedDefinitionsConverge(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()

	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatalf("create p1: %v", err)
	}
	if _, err := a.CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err != nil {
		t.Fatalf("create p2: %v", err)
	}
	if _, err := a.AddDependency(context.Background(), "p1", "p2"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := a.SetRuleEnabled(context.Background(), "r1", 1, false); err != nil {
		t.Fatalf("set rule enabled: %v", err)
	}
	h.waitConverge()

	for i := 0; i < 3; i++ {
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM posts`); got != 2 {
			t.Fatalf("node %d posts=%d", i, got)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
			t.Fatalf("node %d deps=%d", i, got)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM rules`); got != 1 {
			t.Fatalf("node %d rules=%d", i, got)
		}
		var enabled int
		if err := h.dbs[i].QueryRow(`SELECT enabled FROM rules WHERE id='r1'`).Scan(&enabled); err != nil || enabled != 0 {
			t.Fatalf("node %d rule enabled=%d err=%v", i, enabled, err)
		}
		if h.fsms[i].GraphRevision() != 1 {
			t.Fatalf("node %d graph revision=%d want 1", i, h.fsms[i].GraphRevision())
		}
	}
}

// TestPassiveReplicaDoesNotExecute proves installing definitions never creates
// node-local alerts/incidents/notifications; a passive replica does not
// evaluate or execute merely from holding a definition.
func TestPassiveReplicaDoesNotExecute(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "firing", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// The FSM materializes definitions only; it never writes evaluation/execution
	// state. Replaying the missing_policy=firing rule on any replica must not
	// create alerts/incidents/notifications/check state.
	for i := 0; i < 3; i++ {
		for _, tbl := range []string{"alerts", "incidents", "notification_deliveries"} {
			if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM `+tbl); got != 0 {
				t.Fatalf("node %d %s=%d (passive replica must not execute)", i, tbl, got)
			}
		}
	}
}

// TestDeleteWithDifferingLocalHistory proves the A/B/C post.delete contract:
// identical replicated definitions + identical graph revision across nodes
// with different node-local histories, local FK children cleaned where present.
func TestDeleteWithDifferingLocalHistory(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(context.Background(), "p1", "p1"); err == nil {
		t.Fatal("self dependency must be rejected")
	}

	// Inject differing node-local history per node (post-delete prerequisite).
	// Node 0: substantial (observations, alerts, logs, collector key, device).
	// Node 1: different (logs, changes). Node 2: none.
	mustExec(t, h.dbs[0], `INSERT INTO collector_keys(id,post_id,secret_hash,last_sequence) VALUES('ck','p1',x'01',0)`)
	mustExec(t, h.dbs[0], `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES('p1','ck','t','t',1,'cpu',90,'%','good','{}')`)
	mustExec(t, h.dbs[0], `INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at) VALUES('r1','p1','open','warning','t','t')`)
	mustExec(t, h.dbs[0], `INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p1','sys','t','t','info','boot')`)
	mustExec(t, h.dbs[0], `INSERT INTO device_profiles(id,post_id,kind,address,port,username,created_at) VALUES('dp','p1','snmp','1.2.3.4',161,'u','t')`)
	mustExec(t, h.dbs[1], `INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p1','sys','t','t','warn','disk')`)
	mustExec(t, h.dbs[1], `INSERT INTO changes(post_id,kind,occurred_at,actor,summary) VALUES('p1','update','t','u','changed')`)

	if _, err := a.DeletePost(context.Background(), "p1"); err != nil {
		t.Fatalf("delete post: %v", err)
	}
	h.waitConverge()

	for i := 0; i < 3; i++ {
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM posts WHERE id='p1'`); got != 0 {
			t.Fatalf("node %d post p1 still present", i)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM rules`); got != 0 {
			t.Fatalf("node %d rules not cleaned", i)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM post_dependencies`); got != 0 {
			t.Fatalf("node %d deps not cleaned", i)
		}
		if h.fsms[i].GraphRevision() != 1 {
			t.Fatalf("node %d graph revision=%d want 1 (post.delete is one graph-changing op)", i, h.fsms[i].GraphRevision())
		}
		// Local FK children cleaned where present; absent tables are no-ops.
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM observations`); got != 0 {
			t.Fatalf("node %d observations not cleaned", i)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM alerts`); got != 0 {
			t.Fatalf("node %d alerts not cleaned", i)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM logs`); got != 0 {
			t.Fatalf("node %d logs not cleaned", i)
		}
		if got := count(t, h.dbs[i], `SELECT COUNT(*) FROM collector_keys`); got != 0 {
			t.Fatalf("node %d collector keys not cleaned", i)
		}
	}
}

// TestDependencyCycleRejected proves a second edge that would create a cycle
// is rejected before consensus.
func TestDependencyCycleRejected(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	mustCreate := func(id string) {
		t.Helper()
		if _, err := a.CreatePost(context.Background(), id, mkPost(id, "host")); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	mustCreate("p1")
	mustCreate("p2")
	mustCreate("p3")
	if _, err := a.AddDependency(context.Background(), "p1", "p2"); err != nil {
		t.Fatalf("edge p1->p2: %v", err)
	}
	// p2->p1 would close a cycle (p1->p2 exists).
	if _, err := a.AddDependency(context.Background(), "p2", "p1"); err == nil {
		t.Fatal("dependency cycle must be rejected")
	}
	// A non-cyclic edge still succeeds.
	if _, err := a.AddDependency(context.Background(), "p2", "p3"); err != nil {
		t.Fatalf("edge p2->p3: %v", err)
	}
	if h.fsms[0].GraphRevision() != 2 {
		t.Fatalf("graph revision=%d want 2 (one accepted graph edge)", h.fsms[0].GraphRevision())
	}
}

// TestStaleDomainRevisionFailsClosed proves a stale graph operation (validated
// against an outdated graph revision) fails closed deterministically at apply.
func TestStaleDomainRevisionFailsClosed(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	mustCreate := func(id string) {
		t.Helper()
		if _, err := a.CreatePost(context.Background(), id, mkPost(id, "host")); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	mustCreate("p1")
	mustCreate("p2")
	// Capture graph revision G, then commit a graph edge (advances to G+1).
	if _, err := a.AddDependency(context.Background(), "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	// Build a stale dependency operation carrying DomainRevision=G and propose
	// it directly (simulating validation under a dead/older leader).
	op, err := buildOperation("dep:p2:p1", "watchpost", KindDependencyAdd, "p2", 0, 1, depPayload{DependsOn: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.leaderNode().Propose(context.Background(), op); err == nil {
		t.Fatal("stale graph operation must fail closed at apply")
	}
	// The graph is unchanged (no edge p2->p1) and revision still advanced once.
	if got := count(t, h.dbs[0], `SELECT COUNT(*) FROM post_dependencies WHERE post_id='p2'`); got != 0 {
		t.Fatal("stale edge must not be applied")
	}
	if h.fsms[0].GraphRevision() != 1 {
		t.Fatalf("graph revision=%d want 1", h.fsms[0].GraphRevision())
	}
}

// TestPostUpdateStaleRevision proves optimistic-concurrency revision
// preconditions fail closed at apply.
func TestPostUpdateStaleRevision(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpdatePost(context.Background(), "p1", 1, mkPost("host-a2", "host")); err != nil {
		t.Fatalf("update rev 1: %v", err)
	}
	if _, err := a.UpdatePost(context.Background(), "p1", 1, mkPost("host-a3", "host")); err == nil {
		t.Fatal("stale post revision must fail closed")
	}
	var v int64
	if err := h.dbs[0].QueryRow(`SELECT version FROM posts WHERE id='p1'`).Scan(&v); err != nil || v != 2 {
		t.Fatalf("post version=%d want 2", v)
	}
}

// TestSnapshotRestorePreservesGraphRevision proves the product snapshot
// carries posts, dependency edges and the graph revision across export/install.
func TestSnapshotRestorePreservesGraphRevision(t *testing.T) {
	h := newHarness(t, 1)
	a := h.leader()
	mustCreate := func(id string) {
		t.Helper()
		if _, err := a.CreatePost(context.Background(), id, mkPost(id, "host")); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	mustCreate("p1")
	mustCreate("p2")
	if _, err := a.AddDependency(context.Background(), "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Export the product snapshot and install it onto a fresh standalone node.
	snap, err := h.nodes[0].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t)
	fresh, err := NewFSM(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Restore(io.NopCloser(bytes.NewReader(snap))); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM posts`); got != 2 {
		t.Fatalf("restored posts=%d", got)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
		t.Fatalf("restored deps=%d", got)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM rules`); got != 1 {
		t.Fatalf("restored rules=%d", got)
	}
	if fresh.GraphRevision() != h.fsms[0].GraphRevision() {
		t.Fatalf("restored graph revision=%d want %d", fresh.GraphRevision(), h.fsms[0].GraphRevision())
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// TestDependencyAdmissionRace proves validation and DomainRevision capture are
// atomic: two individually-valid dependency intents that would jointly form a
// cycle cannot both be admitted. X validates against G, pauses in the
// admission lock; Y is enqueued behind X; X commits; Y is then validated
// against the post-X graph and rejected as a cycle BEFORE consensus - never a
// committed stale operation.
func TestDependencyAdmissionRace(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	ctx := context.Background()
	for _, id := range []string{"A", "B", "C"} {
		if _, err := a.CreatePost(ctx, id, mkPost(id, "host")); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if _, err := a.AddDependency(ctx, "A", "B"); err != nil {
		t.Fatalf("edge A->B: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var barrier sync.Once
	a.BeforeGraphValidate = func() {
		barrier.Do(func() {
			close(entered)
			<-release
		})
	}

	// X: B->C (valid against the pre-X graph). It holds the admission lock.
	xDone := make(chan error, 1)
	go func() {
		_, err := a.AddDependency(ctx, "B", "C")
		xDone <- err
	}()
	<-entered

	// Y: C->A. Individually valid before X; after X (A->B, B->C) it closes a
	// cycle. Y must block behind X and be validated against the post-X graph.
	yDone := make(chan error, 1)
	go func() {
		_, err := a.AddDependency(ctx, "C", "A")
		yDone <- err
	}()
	time.Sleep(100 * time.Millisecond)

	close(release)
	if err := <-xDone; err != nil {
		t.Fatalf("X (B->C) failed: %v", err)
	}
	if err := <-yDone; err == nil {
		t.Fatal("Y (C->A) must be rejected as a cycle after X committed")
	}
	h.waitConverge()

	if got := count(t, h.dbs[0], `SELECT COUNT(*) FROM post_dependencies`); got != 2 {
		t.Fatalf("deps=%d want 2 (A->B, B->C)", got)
	}
	if got := count(t, h.dbs[0], `SELECT COUNT(*) FROM post_dependencies WHERE post_id='C'`); got != 0 {
		t.Fatal("C->A must not be admitted")
	}
	if h.fsms[0].GraphRevision() != 2 {
		t.Fatalf("graph revision=%d want 2", h.fsms[0].GraphRevision())
	}
}

// TestDependencyAddRacesPostDelete proves post.delete participates in the same
// graph-mutation serialization: a dependency-add racing a post.delete is
// validated against the post-delete graph and rejected before consensus.
func TestDependencyAddRacesPostDelete(t *testing.T) {
	h := newHarness(t, 3)
	a := h.leader()
	ctx := context.Background()
	for _, id := range []string{"A", "B"} {
		if _, err := a.CreatePost(ctx, id, mkPost(id, "host")); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if _, err := a.AddDependency(ctx, "A", "B"); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var barrier sync.Once
	a.BeforeGraphValidate = func() {
		barrier.Do(func() {
			close(entered)
			<-release
		})
	}
	xDone := make(chan error, 1)
	go func() {
		_, err := a.DeletePost(ctx, "A")
		xDone <- err
	}()
	<-entered
	yDone := make(chan error, 1)
	go func() {
		_, err := a.AddDependency(ctx, "B", "A")
		yDone <- err
	}()
	time.Sleep(100 * time.Millisecond)

	close(release)
	if err := <-xDone; err != nil {
		t.Fatalf("post.delete failed: %v", err)
	}
	yErr := <-yDone
	h.waitConverge()

	if got := count(t, h.dbs[0], `SELECT COUNT(*) FROM posts WHERE id='A'`); got != 0 {
		t.Fatal("post A must be deleted")
	}
	if yErr == nil {
		t.Fatal("B->A must be rejected: endpoint A no longer exists after the delete")
	}
	if h.fsms[0].GraphRevision() != 2 {
		t.Fatalf("graph revision=%d want 2 (add + delete)", h.fsms[0].GraphRevision())
	}
}
