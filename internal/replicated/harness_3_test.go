package replicated

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// openDBAt opens a file-backed product SQLite with the replicated test schema.
// It is idempotent so a durable product DB survives restart/reopen.
func openDBAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	idempotent := strings.ReplaceAll(testSchema, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
	if _, err := db.Exec(idempotent); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func waitSingleLeader(t *testing.T, d *durableNode) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && d.node.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if d.node.State() != raft.Leader {
		t.Fatal("node did not become leader")
	}
}

// durableNode is a product node with bbolt raft log/stable, a file snapshot
// store and a persistent product SQLite, so restart/catch-up is provable.
type durableNode struct {
	node    *replication.Node
	fsm     *FSM
	db      *sql.DB
	store   *replication.BoltStore
	raftDir string
	dbPath  string
}

func newDurableNode(t *testing.T, id raft.ServerID, raftDir, dbPath string, fabric *replication.Fabric, bootstrap bool) *durableNode {
	t.Helper()
	db := openDBAt(t, dbPath)
	fsm, err := NewFSM(db)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := replication.NewBoltStore(filepath.Join(raftDir, "raft.db"))
	if err != nil {
		t.Fatal(err)
	}
	snaps, err := raft.NewFileSnapshotStore(filepath.Join(raftDir, "snap"), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := raft.ServerAddress("node-" + string(id))
	nt := replication.NewNodeTransport(id, addr, fabric)
	node, err := replication.NewNode(replication.NodeOptions{
		ID: id, Address: addr, Transport: nt,
		LogStore: bs, StableStore: bs, SnapshotStore: snaps,
		Fabric: fabric, FSM: fsm, Bootstrap: bootstrap,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	fabric.RegisterNode(node)
	return &durableNode{node: node, fsm: fsm, db: db, store: bs, raftDir: raftDir, dbPath: dbPath}
}

func (d *durableNode) close() {
	_ = d.node.Shutdown()
	_ = d.store.Close()
	_ = d.db.Close()
}

func durableAdapter(d *durableNode) *Adapter { return NewAdapter(d.node, d.fsm, d.db, "watchpost") }

func waitDurableLeader(t *testing.T, nodes []*durableNode) int {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for i, n := range nodes {
			if n.node.State() == raft.Leader {
				return i
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no leader among durable nodes")
	return -1
}

func durableConverge(t *testing.T, nodes []*durableNode, leaderIdx int) {
	t.Helper()
	la, _ := nodes[leaderIdx].node.AppliedIndex()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, n := range nodes {
			da, _ := n.node.AppliedIndex()
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
	t.Fatal("durable nodes did not converge")
}

// TestProductNodeRestartRecovery proves a durable product node recovers its
// replicated definitions and dependency-graph revision from the durable raft
// log/snapshot and product SQLite across a clean shutdown/reopen.
func TestProductNodeRestartRecovery(t *testing.T) {
	raftDir, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "repl.db")
	fabric := replication.NewFabric()
	d := newDurableNode(t, "n1", raftDir, dbPath, fabric, true)
	waitSingleLeader(t, d)
	a := durableAdapter(d)
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(context.Background(), "p1", "p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d.close()

	fabric2 := replication.NewFabric()
	d2 := newDurableNode(t, "n1", raftDir, dbPath, fabric2, true)
	defer func() { d2.close() }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && d2.node.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if d2.node.State() != raft.Leader {
		t.Fatal("reopened node did not become leader")
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts`); got != 2 {
		t.Fatalf("recovered posts=%d", got)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
		t.Fatalf("recovered deps=%d", got)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM rules`); got != 1 {
		t.Fatalf("recovered rules=%d", got)
	}
	if d2.fsm.GraphRevision() != 1 {
		t.Fatalf("recovered graph revision=%d want 1", d2.fsm.GraphRevision())
	}
	// Continue writing after restart.
	if _, err := durableAdapter(d2).CreatePost(context.Background(), "p3", mkPost("host-c", "host")); err != nil {
		t.Fatalf("continue writing after restart: %v", err)
	}
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts`); got != 3 {
		t.Fatalf("posts after continue=%d", got)
	}
}

// TestProductSnapshotCatchUp proves an isolated learner that fell behind
// installs the PRODUCT semantic snapshot and replays the trailing log,
// converging to identical definitions and dependency-graph revision.
func TestProductSnapshotCatchUp(t *testing.T) {
	fabric := replication.NewFabric()
	dirs := make([]string, 4)
	dbpaths := make([]string, 4)
	nodes := make([]*durableNode, 0, 4)
	defer func() {
		for _, n := range nodes {
			n.close()
		}
	}()
	for i := 0; i < 4; i++ {
		id := raft.ServerID(fmt.Sprintf("n%d", i+1))
		dirs[i] = t.TempDir()
		dbpaths[i] = filepath.Join(t.TempDir(), "repl.db")
		nodes = append(nodes, newDurableNode(t, id, dirs[i], dbpaths[i], fabric, i == 0))
	}
	for i := 1; i < 3; i++ {
		id := raft.ServerID(fmt.Sprintf("n%d", i+1))
		addr := raft.ServerAddress("node-" + string(id))
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			li := waitDurableLeader(t, nodes)
			if err := nodes[li].node.AddVoter(id, addr); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Learner n4: add as non-voter and isolate before it catches up.
	lid := raft.ServerID("n4")
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		li := waitDurableLeader(t, nodes)
		if err := nodes[li].node.AddNonvoter(lid, raft.ServerAddress("node-n4")); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fabric.Isolate("n4")

	a := durableAdapter(nodes[waitDurableLeader(t, nodes)])
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("p%d", i+10)
		if _, err := a.CreatePost(context.Background(), id, mkPost(id, "host")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.AddDependency(context.Background(), "p1", "p10"); err != nil {
		t.Fatal(err)
	}
	li := waitDurableLeader(t, nodes)
	if err := nodes[li].node.Snapshot(); err != nil {
		t.Fatal(err)
	}
	durableConverge(t, nodes[:3], li)

	// Reconnect the learner: it must install the product snapshot + trailing log.
	fabric.Reconnect("n4")
	deadline = time.Now().Add(30 * time.Second)
	la, _ := nodes[li].node.AppliedIndex()
	for time.Now().Before(deadline) {
		da, _ := nodes[3].node.AppliedIndex()
		if da >= la {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := count(t, nodes[3].db, `SELECT COUNT(*) FROM posts`); got != 16 {
		t.Fatalf("learner posts=%d want 16", got)
	}
	if got := count(t, nodes[3].db, `SELECT COUNT(*) FROM post_dependencies`); got != 1 {
		t.Fatalf("learner deps=%d", got)
	}
	if nodes[3].fsm.GraphRevision() != nodes[li].fsm.GraphRevision() {
		t.Fatalf("learner graph revision=%d want %d", nodes[3].fsm.GraphRevision(), nodes[li].fsm.GraphRevision())
	}
}

// TestProductCompleteClusterRestart proves all durable product nodes recover
// after a full cluster restart (persisted configuration, snapshots, product
// DBs) and continue replicating.
func TestProductCompleteClusterRestart(t *testing.T) {
	raftDirs := make([]string, 3)
	dbPaths := make([]string, 3)
	for i := 0; i < 3; i++ {
		raftDirs[i] = t.TempDir()
		dbPaths[i] = filepath.Join(t.TempDir(), "repl.db")
	}
	build := func(fabric *replication.Fabric) []*durableNode {
		out := make([]*durableNode, 0, 3)
		for i := 0; i < 3; i++ {
			id := raft.ServerID(fmt.Sprintf("n%d", i+1))
			out = append(out, newDurableNode(t, id, raftDirs[i], dbPaths[i], fabric, i == 0))
		}
		for i := 1; i < 3; i++ {
			id := raft.ServerID(fmt.Sprintf("n%d", i+1))
			addr := raft.ServerAddress("node-" + string(id))
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				li := waitDurableLeader(t, out)
				if err := out[li].node.AddVoter(id, addr); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		return out
	}

	first := build(replication.NewFabric())
	li := waitDurableLeader(t, first)
	a := durableAdapter(first[li])
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateRule(context.Background(), "r1", RulePayload{PostID: "p1", Signal: "cpu", Operator: "gt", Threshold: 80, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := first[li].node.Snapshot(); err != nil {
		t.Fatal(err)
	}
	for _, n := range first {
		n.close()
	}

	second := build(replication.NewFabric())
	defer func() {
		for _, n := range second {
			n.close()
		}
	}()
	li2 := waitDurableLeader(t, second)
	durableConverge(t, second, li2)
	for _, n := range second {
		if got := count(t, n.db, `SELECT COUNT(*) FROM posts`); got != 1 {
			t.Fatalf("restarted node posts=%d", got)
		}
		if n.fsm.GraphRevision() != first[0].fsm.GraphRevision() {
			t.Fatalf("restarted graph revision=%d want %d", n.fsm.GraphRevision(), first[0].fsm.GraphRevision())
		}
	}
	if _, err := durableAdapter(second[li2]).CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err != nil {
		t.Fatalf("continue after full restart: %v", err)
	}
	durableConverge(t, second, li2)
	for _, n := range second {
		if got := count(t, n.db, `SELECT COUNT(*) FROM posts`); got != 2 {
			t.Fatalf("posts after continue=%d", got)
		}
	}
}

// TestSnapshotRestorePreservesNodeLocal proves installing a product snapshot
// onto a fresh node transfers replicated definitions + graph revision while
// preserving D's own node-local identity/credentials and unrelated node-local
// product state; the source's node-local state never leaves the source.
func TestSnapshotRestorePreservesNodeLocal(t *testing.T) {
	h := newHarness(t, 1)
	a := h.leader()
	ctx := context.Background()
	if _, err := a.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDependency(ctx, "p1", "p1"); err == nil {
		t.Fatal("self dependency must be rejected")
	}
	mustExec(t, h.dbs[0], `CREATE TABLE IF NOT EXISTS local_settings(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, h.dbs[0], `INSERT INTO local_settings(k,v) VALUES('src_secret','secret-a')`)
	h.nodes[0].SetLocal("node.identity", "a")
	h.nodes[0].SetLocal("node.credential", "cred-a")

	snap, err := h.nodes[0].ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}

	// Fresh node D with its own node-local identity/credentials and local state.
	fabric := replication.NewFabric()
	snaps, err := raft.NewFileSnapshotStore(t.TempDir(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	dDB := openTestDB(t)
	mustExec(t, dDB, `CREATE TABLE IF NOT EXISTS local_settings(k TEXT PRIMARY KEY, v TEXT)`)
	mustExec(t, dDB, `INSERT INTO local_settings(k,v) VALUES('dst_secret','secret-d')`)
	seedMeta(t, dDB, 1, 1, 0)
	dFSM, err := NewFSM(dDB)
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
	// Replicated definitions + graph revision transferred.
	if got := count(t, dDB, `SELECT COUNT(*) FROM posts`); got != 1 {
		t.Fatalf("D posts=%d", got)
	}
	if dFSM.GraphRevision() != 0 {
		t.Fatalf("D graph revision=%d want 0 (no accepted graph edge)", dFSM.GraphRevision())
	}
	// D's own node-local identity/credentials preserved; A's absent.
	if v, ok := dNode.GetLocal("node.identity"); !ok || v != "d" {
		t.Fatalf("D identity not preserved: %q ok=%v", v, ok)
	}
	if v, ok := dNode.GetLocal("node.credential"); !ok || v != "cred-d" {
		t.Fatalf("D credential not preserved: %q ok=%v", v, ok)
	}
	if v, ok := dNode.GetLocal("node.credential"); ok && v == "cred-a" {
		t.Fatal("A's node-local credential leaked into D")
	}
	// D's own unrelated node-local product state preserved; A's never present.
	var dv string
	if err := dDB.QueryRow(`SELECT v FROM local_settings WHERE k='dst_secret'`).Scan(&dv); err != nil || dv != "secret-d" {
		t.Fatalf("D local settings not preserved: %q err=%v", dv, err)
	}
	if got := count(t, dDB, `SELECT COUNT(*) FROM local_settings WHERE k='src_secret'`); got != 0 {
		t.Fatal("A's local settings leaked into D")
	}
}

// TestStandaloneCoexistence proves a standalone product DB (no raft, no
// replication) holds independent local state and is untouched by a replicated
// cluster; replication is opt-in.
func TestStandaloneCoexistence(t *testing.T) {
	// Standalone DB written directly via the product SQL path (replication
	// disabled), with the propagation gate off.
	standalone := openTestDB(t)
	mustExec(t, standalone, `INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('ps','standalone','host','t','t')`)

	// A separate replicated cluster holds its own definitions.
	h := newHarness(t, 1)
	a := h.leader()
	if _, err := a.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if got := count(t, standalone, `SELECT COUNT(*) FROM posts`); got != 1 {
		t.Fatalf("standalone posts=%d want 1", got)
	}
	if got := count(t, h.dbs[0], `SELECT COUNT(*) FROM posts`); got != 1 {
		t.Fatalf("replicated posts=%d want 1", got)
	}
	if count(t, standalone, `SELECT COUNT(*) FROM posts WHERE id='p1'`) != 0 {
		t.Fatal("replicated definitions must not appear in the standalone DB")
	}
	// The propagation gate is off by default: propagation applies are not gated.
	if IsReplicatedEnabled() {
		t.Fatal("replicated gate must be disabled by default")
	}
}
