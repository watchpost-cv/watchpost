package replicated

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// seedLocalHistory injects node-local FK-valid rows for a post (observations,
// alerts, logs, conversations, action requests, collector key) plus a user.
func seedLocalHistory(t *testing.T, db *sql.DB) (map[string]int, func(*sql.DB)) {
	t.Helper()
	mustExec(t, db, `INSERT INTO users(id) VALUES(1)`)
	mustExec(t, db, `INSERT INTO collector_keys(id,post_id,secret_hash,last_sequence) VALUES('ck','p1',x'01',0)`)
	mustExec(t, db, `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES('p1','ck','t','t',1,'cpu',90,'%','good','{}')`)
	mustExec(t, db, `INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at) VALUES('r1','p1','open','warning','t','t')`)
	mustExec(t, db, `INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p1','sys','t','t','info','boot')`)
	mustExec(t, db, `INSERT INTO conversations(user_id,post_id,created_at) VALUES(1,'p1','t')`)
	mustExec(t, db, `INSERT INTO action_requests(type,post_id,parameters_json,state) VALUES('run','p1','{}','pending')`)
	keys := []string{"observations", "alerts", "logs", "conversations", "action_requests", "collector_keys"}
	before := map[string]int{}
	for _, k := range keys {
		before[k] = count(t, db, `SELECT COUNT(*) FROM `+k)
	}
	return before, func(check *sql.DB) {
		for _, k := range keys {
			if got := count(t, check, `SELECT COUNT(*) FROM `+k); got != before[k] {
				t.Fatalf("node-local %s changed across restart/recovery: got %d want %d", k, got, before[k])
			}
		}
	}
}

// seedMeta writes consistent replication-adapter metadata, as atomic applies
// would have left it.
func seedMeta(t *testing.T, db *sql.DB, idx, term uint64, graphRev int64) {
	t.Helper()
	mustExec(t, db, `CREATE TABLE IF NOT EXISTS _replicated_meta(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, db, `INSERT INTO _replicated_meta(k,v) VALUES('applied_index',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprintf("%d", idx))
	mustExec(t, db, `INSERT INTO _replicated_meta(k,v) VALUES('applied_term',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprintf("%d", term))
	mustExec(t, db, `INSERT INTO _replicated_meta(k,v) VALUES('graph_revision',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprintf("%d", graphRev))
}

// TestRestartPreservesNodeLocalHistory proves an ordinary durable restart with
// both replicated definitions and substantial node-local history recovers the
// replicated state + graph revision while preserving ALL node-local history.
func TestRestartPreservesNodeLocalHistory(t *testing.T) {
	raftDir, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "repl.db")
	d := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	waitSingleLeader(t, d)
	a := durableAdapter(d)
	ctx := context.Background()
	if _, err := a.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreatePost(ctx, "p2", mkPost("host-b", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(ctx, "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(ctx, "r1", rulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, assertLocal := seedLocalHistory(t, d.db)
	d.close()

	d2 := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	defer d2.close()
	waitSingleLeader(t, d2)
	// Replicated definitions + graph revision recovered.
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts`); got != 2 {
		t.Fatalf("recovered posts=%d", got)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM rules`); got != 1 {
		t.Fatalf("recovered rules=%d", got)
	}
	if d2.fsm.GraphRevision() != 1 {
		t.Fatalf("recovered graph revision=%d want 1", d2.fsm.GraphRevision())
	}
	// ALL node-local history still present (the durable recovery must not erase it).
	assertLocal(d2.db)
}

// TestRecoveryFailurePreservesNodeLocal proves FSM construction does not
// destructively clear node-local state even when raft recovery never completes
// (corrupt snapshot / disk error / crash before rejoin).
func TestRecoveryFailurePreservesNodeLocal(t *testing.T) {
	db := openTestDB(t)
	mustExec(t, db, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p1','host-a','host','t','t')`)
	mustExec(t, db, `INSERT INTO rules(id,post_id,signal,operator,threshold,missing_policy,severity,enabled,version) VALUES('r1','p1','cpu','gt',80,'unknown','warning',1,1)`)
	_, assertLocal := seedLocalHistory(t, db)
	// The injected materialization is consistent: seed the replication metadata
	// that atomic applies would have written.
	seedMeta(t, db, 1, 1, 0)

	// Construct the FSM (the step the old model used to clear) WITHOUT any raft
	// recovery. It must not erase replicated or node-local state.
	fsm, err := NewFSM(db)
	if err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM posts`); got != 1 {
		t.Fatalf("posts after NewFSM=%d", got)
	}
	if got := count(t, db, `SELECT COUNT(*) FROM rules`); got != 1 {
		t.Fatalf("rules after NewFSM=%d", got)
	}
	assertLocal(db)
	_ = fsm
}

// TestNonFreshSnapshotInstall proves installing a product snapshot onto a
// non-fresh destination (D has its own identity/credentials and local history
// for the represented definitions) yields correct replicated state, preserves
// unrelated node-local state, applies the frozen snapshot-replacement policy to
// FK-referencing local children, and never imports source-local state.
func TestNonFreshSnapshotInstall(t *testing.T) {
	h := newHarness(t, 1)
	a := h.leader()
	ctx := context.Background()
	if _, err := a.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreatePost(ctx, "p2", mkPost("host-b", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(ctx, "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(ctx, "r1", rulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Source-local node-local state (must never leave the source).
	mustExec(t, h.dbs[0], `CREATE TABLE IF NOT EXISTS local_settings(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, h.dbs[0], `INSERT INTO local_settings(k,v) VALUES('src','secret-a')`)
	snap, err := h.nodes[0].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	// Non-fresh destination D with its own identity/credentials, unrelated local
	// state, and local history for the snapshot's post.
	dDB := openTestDB(t)
	mustExec(t, dDB, `CREATE TABLE IF NOT EXISTS local_settings(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, dDB, `INSERT INTO local_settings(k,v) VALUES('dst','secret-d')`)
	// D already has a replicated post p1 with local history.
	mustExec(t, dDB, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p1','old','host','t','t')`)
	mustExec(t, dDB, `INSERT INTO rules(id,post_id,signal,operator,threshold,missing_policy,severity,enabled,version) VALUES('r1','p1','cpu','gt',80,'unknown','warning',1,1)`)
	seedLocalHistory(t, dDB)
	seedMeta(t, dDB, 1, 1, 0)
	dFSM, err := NewFSM(dDB)
	if err != nil {
		t.Fatal(err)
	}

	fabric := replication.NewFabric()
	snaps, err := raft.NewFileSnapshotStore(t.TempDir(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	nt := replication.NewNodeTransport("d", "node-d", fabric)
	dNode, err := replication.NewNode(replication.NodeOptions{
		ID: "d", Address: "node-d", Transport: nt,
		LogStore: raft.NewInmemStore(), StableStore: raft.NewInmemStore(), SnapshotStore: snaps,
		Fabric: fabric, FSM: dFSM, Bootstrap: true,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dNode.Shutdown()
	dNode.SetLocal("node.identity", "d")
	dNode.SetLocal("node.credential", "cred-d")
	if err := dNode.ApplySnapshot(snap); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Replicated state matches the snapshot.
	if got := count(t, dDB, `SELECT COUNT(*) FROM posts`); got != 2 {
		t.Fatalf("D posts=%d want 2", got)
	}
	if got := count(t, dDB, `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
		t.Fatalf("D deps=%d", got)
	}
	if got := count(t, dDB, `SELECT COUNT(*) FROM rules`); got != 1 {
		t.Fatalf("D rules=%d", got)
	}
	if dFSM.GraphRevision() != 1 {
		t.Fatalf("D graph revision=%d want 1", dFSM.GraphRevision())
	}
	// D's own identity/credentials and unrelated local state preserved.
	if v, ok := dNode.GetLocal("node.identity"); !ok || v != "d" {
		t.Fatalf("D identity not preserved: %q", v)
	}
	if v, ok := dNode.GetLocal("node.credential"); !ok || v != "cred-d" {
		t.Fatalf("D credential not preserved: %q", v)
	}
	if v := count(t, dDB, `SELECT COUNT(*) FROM local_settings WHERE k='dst'`); v != 1 {
		t.Fatal("D unrelated local state lost")
	}
	if v := count(t, dDB, `SELECT COUNT(*) FROM local_settings WHERE k='src'`); v != 0 {
		t.Fatal("source-local state imported into D")
	}
	// FK-referencing local children follow the frozen snapshot-replacement
	// policy (cleared for the replaced definitions because the FK schema cannot
	// keep rows referencing a replaced post); unrelated local rows survive.
	for _, k := range []string{"observations", "alerts", "logs", "conversations", "action_requests", "collector_keys"} {
		if got := count(t, dDB, `SELECT COUNT(*) FROM `+k); got != 0 {
			t.Fatalf("snapshot replacement policy: %s=%d want 0 (FK child cleared)", k, got)
		}
	}
}

// TestRestartWithForcedSnapshotPreservesNodeLocal forces a persisted raft
// snapshot at index S, continues committing to P > S, seeds node-local history,
// then restarts. HashiCorp Raft restores the persisted snapshot (S) before
// replaying the trailing log; the FSM must recognize S <= P and NOT
// destructively replace the current materialization or erase node-local
// history. Durable op-ID knowledge and graph revision must survive.
func TestRestartWithForcedSnapshotPreservesNodeLocal(t *testing.T) {
	raftDir, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "repl.db")
	d := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	waitSingleLeader(t, d)
	ctx := context.Background()

	// A create with a FIXED op-ID so durable op-ID retry semantics are testable.
	op, err := buildOperation("post-fixed", "watchpost", KindPostCreate, "pfixed", 0, 0, mkPost("fixed", "host"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.node.Propose(ctx, op); err != nil {
		t.Fatalf("fixed create: %v", err)
	}
	a := durableAdapter(d)
	if _, err := a.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreatePost(ctx, "p2", mkPost("host-b", "host")); err != nil {
		t.Fatal(err)
	}
	// Force a persisted raft snapshot (index S), then continue past it.
	if err := d.node.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(ctx, "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(ctx, "r1", rulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, assertLocal := seedLocalHistory(t, d.db)
	d.close()

	d2 := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	defer d2.close()
	waitSingleLeader(t, d2)
	// Replicated definitions through P and graph revision recovered.
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts`); got != 3 {
		t.Fatalf("posts=%d want 3 (pfixed,p1,p2)", got)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
		t.Fatalf("deps=%d want 1", got)
	}
	if d2.fsm.GraphRevision() != 1 {
		t.Fatalf("graph revision=%d want 1", d2.fsm.GraphRevision())
	}
	// NODE-LOCAL history preserved (older snapshot restore must not erase it).
	assertLocal(d2.db)
	// Durable op-ID retry: retrying the fixed create resolves to the committed
	// result with no second mutation.
	retry, err := d2.node.Propose(ctx, op)
	if err != nil {
		t.Fatalf("op-ID retry after forced-snapshot restart: %v", err)
	}
	if retry.OpID != "post-fixed" || retry.Index == 0 {
		t.Fatalf("unexpected retry result: %+v", retry)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts WHERE id='pfixed'`); got != 1 {
		t.Fatal("op-ID retry double-applied the create")
	}
}

// TestRestartWithSnapshotEqualIndex proves restart recovery where the persisted
// snapshot index equals the materialized index does not needlessly erase
// node-local history.
func TestRestartWithSnapshotEqualIndex(t *testing.T) {
	raftDir, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "repl.db")
	d := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	waitSingleLeader(t, d)
	a := durableAdapter(d)
	ctx := context.Background()
	if _, err := a.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(ctx, "r1", rulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, assertLocal := seedLocalHistory(t, d.db)
	if err := d.node.Snapshot(); err != nil {
		t.Fatal(err)
	}
	d.close()

	d2 := newDurableNode(t, "n1", raftDir, dbPath, replication.NewFabric(), true)
	defer d2.close()
	waitSingleLeader(t, d2)
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts`); got != 1 {
		t.Fatalf("posts=%d", got)
	}
	assertLocal(d2.db)
}

// TestMalformedMetaFailsClosed proves inconsistent replication metadata is
// never silently treated as a fresh database.
func TestMalformedMetaFailsClosed(t *testing.T) {
	// Materialization without metadata -> fail closed.
	db := openTestDB(t)
	mustExec(t, db, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p1','host-a','host','t','t')`)
	if _, err := NewFSM(db); err == nil {
		t.Fatal("materialization without replication metadata must fail closed")
	}
	db.Close()

	// Malformed applied_index -> fail closed.
	db2 := openTestDB(t)
	mustExec(t, db2, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p1','host-a','host','t','t')`)
	mustExec(t, db2, `CREATE TABLE IF NOT EXISTS _replicated_meta(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, db2, `INSERT INTO _replicated_meta(k,v) VALUES('applied_index','not-a-number')`)
	if _, err := NewFSM(db2); err == nil {
		t.Fatal("malformed applied_index must fail closed")
	}
	db2.Close()

	// Malformed graph_revision -> fail closed.
	db3 := openTestDB(t)
	mustExec(t, db3, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p1','host-a','host','t','t')`)
	seedMeta(t, db3, 1, 1, 0)
	mustExec(t, db3, `UPDATE _replicated_meta SET v='x' WHERE k='graph_revision'`)
	if _, err := NewFSM(db3); err == nil {
		t.Fatal("malformed graph_revision must fail closed")
	}
	db3.Close()
}
