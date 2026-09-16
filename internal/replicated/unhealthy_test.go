package replicated

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
)

func waitForCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if count(t, db, query) == want {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q to reach %d (got %d)", query, want, count(t, db, query))
}

func waitApplyFailure(t *testing.T, f *FSM) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f.ApplyFailure() != nil {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("replica did not enter the unhealthy state")
}

// TestCommittedApplyFailureMarksReplicaUnhealthy proves the CP7D-4c contract:
// a committed operation that cannot be deterministically applied on one replica
// leaves the healthy quorum authoritative while that replica enters an explicit
// unhealthy state, rejects authoritative writes, and does not claim healthy
// convergence. The committed operation and the durable materialization
// position of the healthy replicas are preserved.
func TestCommittedApplyFailureMarksReplicaUnhealthy(t *testing.T) {
	h := newHarness(t, 3)
	leaderIdx := h.leaderIndex()
	leader := h.adapters[leaderIdx]

	// Pick one follower (B) to be the unhealthy replica.
	followerIdx := 0
	for followerIdx = 0; followerIdx < 3; followerIdx++ {
		if followerIdx != leaderIdx {
			break
		}
	}
	// Pick the other healthy follower (C).
	otherIdx := 0
	for otherIdx = 0; otherIdx < 3; otherIdx++ {
		if otherIdx != leaderIdx && otherIdx != followerIdx {
			break
		}
	}

	// Inject a committed-apply (replica-health) failure for the next operation
	// on B only. The operation will still be committed by the quorum.
	h.fsms[followerIdx].InjectNextApplyFailure(errors.New("sqlite: simulated replica storage failure"))
	beforeIdx, _ := h.fsms[followerIdx].AppliedIndex()

	if _, err := leader.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatalf("leader create (committed by quorum): %v", err)
	}

	// The healthy quorum (A leader + C) applied the committed operation.
	waitForCount(t, h.dbs[leaderIdx], `SELECT COUNT(*) FROM posts WHERE id='p1'`, 1)
	waitForCount(t, h.dbs[otherIdx], `SELECT COUNT(*) FROM posts WHERE id='p1'`, 1)
	// B has processed the committed operation (asynchronously) and failed it.
	waitApplyFailure(t, h.fsms[followerIdx])

	// B could not realize it: no mutation, unhealthy marker set, position
	// unchanged.
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts WHERE id='p1'`); got != 0 {
		t.Fatalf("unhealthy replica must not apply the committed op: posts=%d", got)
	}
	afterIdx, _ := h.fsms[followerIdx].AppliedIndex()
	if afterIdx != beforeIdx {
		t.Fatalf("failed apply advanced the durable position: %d -> %d", beforeIdx, afterIdx)
	}

	// The unhealthy replica must reject authoritative writes (no local fallback).
	if _, err := h.adapters[followerIdx].CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err == nil {
		t.Fatal("unhealthy replica must reject new authoritative mutations")
	}
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts WHERE id='p2'`); got != 0 {
		t.Fatal("unhealthy replica wrote locally (fail-open)")
	}

	// The healthy leader continues to accept authoritative mutations.
	if _, err := leader.CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err != nil {
		t.Fatalf("healthy leader create after replica failure: %v", err)
	}
	waitForCount(t, h.dbs[otherIdx], `SELECT COUNT(*) FROM posts WHERE id='p2'`, 1)

	// THE FENCING REGRESSION: a later committed operation Y (index > N) must
	// NOT be materialized on the unhealthy replica B on top of the missing N.
	// B stays unhealthy, its position is unchanged, and it contains neither the
	// failed X nor the later unapplied Y.
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts WHERE id='p2'`); got != 0 {
		t.Fatalf("unhealthy replica applied a later committed entry: posts=%d", got)
	}
	if h.fsms[followerIdx].ApplyFailure() == nil {
		t.Fatal("replica B must remain unhealthy after later committed entries")
	}
	afterLater, _ := h.fsms[followerIdx].AppliedIndex()
	if afterLater != beforeIdx {
		t.Fatalf("later committed entries advanced the unhealthy position: %d -> %d", beforeIdx, afterLater)
	}
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts WHERE id='p1'`); got != 0 {
		t.Fatalf("unhealthy replica must not contain the failed committed operation")
	}
}

// TestUnhealthyFencesGraphChangingApply proves an unhealthy replica cannot
// advance dependency-graph metadata for later committed operations. The healthy
// quorum commits a graph-changing operation after the failure; the unhealthy
// replica remains frozen at the pre-failure graph position.
func TestUnhealthyFencesGraphChangingApply(t *testing.T) {
	h := newHarness(t, 3)
	leaderIdx := h.leaderIndex()
	leader := h.adapters[leaderIdx]
	followerIdx := 0
	for followerIdx = 0; followerIdx < 3; followerIdx++ {
		if followerIdx != leaderIdx {
			break
		}
	}
	otherIdx := 0
	for otherIdx = 0; otherIdx < 3; otherIdx++ {
		if otherIdx != leaderIdx && otherIdx != followerIdx {
			break
		}
	}

	h.fsms[followerIdx].InjectNextApplyFailure(errors.New("sqlite: simulated replica storage failure"))
	ctx := context.Background()
	if _, err := leader.CreatePost(ctx, "p1", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.CreatePost(ctx, "p2", mkPost("host-b", "host")); err != nil {
		t.Fatal(err)
	}
	// Graph-changing committed operation after the failure on B.
	if _, err := leader.AddDependency(ctx, "p1", "p2"); err != nil {
		t.Fatalf("healthy leader graph op: %v", err)
	}

	// Healthy quorum converges (graph revision advanced).
	waitForCount(t, h.dbs[otherIdx], `SELECT COUNT(*) FROM post_dependencies WHERE post_id='p1'`, 1)
	waitForCount(t, h.dbs[leaderIdx], `SELECT COUNT(*) FROM post_dependencies WHERE post_id='p1'`, 1)

	// The unhealthy replica is fenced: no posts, no dependency, graph frozen.
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts`); got != 0 {
		t.Fatalf("unhealthy replica materialized posts: %d", got)
	}
	if got := count(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM post_dependencies`); got != 0 {
		t.Fatalf("unhealthy replica materialized a dependency: %d", got)
	}
	if h.fsms[followerIdx].GraphRevision() != 0 {
		t.Fatalf("unhealthy replica advanced graph revision: %d", h.fsms[followerIdx].GraphRevision())
	}
	if h.fsms[followerIdx].ApplyFailure() == nil {
		t.Fatal("replica must remain unhealthy after later committed entries")
	}
}

// TestPersistentApplyFailureRemainsUnhealthyAcrossRestart proves that restart
// with the SAME unresolved failure cause must not magically become healthy: the
// committed operation fails again during reconstruction replay and the replica
// remains unhealthy.
func TestPersistentApplyFailureRemainsUnhealthyAcrossRestart(t *testing.T) {
	raftDir, dbPath := t.TempDir(), filepath.Join(t.TempDir(), "repl.db")
	fabric := replication.NewFabric()
	ctx := context.Background()

	// Run 1: commit X (a post create) with an injected committed-apply failure.
	d1 := newDurableNode(t, "n1", raftDir, dbPath, fabric, true)
	waitSingleLeader(t, d1)
	op, err := buildOperation("post-x", "watchpost", KindPostCreate, "px", 0, 0, mkPost("x", "host"))
	if err != nil {
		t.Fatal(err)
	}
	d1.fsm.InjectApplyFailure("post-x", errors.New("sqlite: persistent replica defect"))
	if _, err := d1.node.Propose(ctx, op); err == nil {
		t.Fatal("committed apply failure must surface")
	}
	if d1.fsm.ApplyFailure() == nil {
		t.Fatal("replica must be unhealthy after the failure")
	}
	d1.close()

	// Run 2: reconstruct with the SAME failure cause present (injected before
	// raft replay). The committed X fails again -> remains unhealthy.
	db2 := openDBAt(t, dbPath)
	fsm2, err := NewFSM(db2)
	if err != nil {
		t.Fatal(err)
	}
	fsm2.InjectApplyFailure("post-x", errors.New("sqlite: persistent replica defect"))
	d2 := buildDurableNode(t, "n1", raftDir, fabric, false, db2, fsm2)
	defer d2.close()
	waitSingleLeader(t, d2)
	// The committed X is replayed during reconstruction and fails again.
	waitApplyFailure(t, d2.fsm)
	if got := count(t, d2.db, `SELECT COUNT(*) FROM posts WHERE id='px'`); got != 0 {
		t.Fatal("failed committed operation must not be materialized")
	}
}

// TestLeaderLocalCommittedApplyFailure proves the leader-local failure case:
// once consensus has committed an operation but the leader cannot apply it, the
// caller sees a failure (never "nothing happened"), the leader becomes
// unhealthy and stops serving authoritative mutations, the committed operation
// is retained on healthy replicas, and the leader's durable position / op-ID
// state do not advance for the failed operation.
func TestLeaderLocalCommittedApplyFailure(t *testing.T) {
	h := newHarness(t, 3)
	leaderIdx := h.leaderIndex()

	// Inject a committed-apply failure on the leader for a known operation.
	op, err := buildOperation("post-bad", "watchpost", KindPostCreate, "p1", 0, 0, mkPost("host-a", "host"))
	if err != nil {
		t.Fatal(err)
	}
	h.fsms[leaderIdx].InjectApplyFailure("post-bad", errors.New("sqlite: simulated leader storage failure"))
	beforeIdx, _ := h.fsms[leaderIdx].AppliedIndex()

	if _, err := h.nodes[leaderIdx].Propose(context.Background(), op); err == nil {
		t.Fatal("leader-local apply failure must surface to the caller")
	}

	// The leader is unhealthy; its durable position and op-ID state did not
	// advance for the failed operation.
	if h.fsms[leaderIdx].ApplyFailure() == nil {
		t.Fatal("leader must be unhealthy after a committed-apply failure")
	}
	afterIdx, _ := h.fsms[leaderIdx].AppliedIndex()
	if afterIdx != beforeIdx {
		t.Fatalf("failed apply advanced the durable position: %d -> %d", beforeIdx, afterIdx)
	}
	if _, ok := h.fsms[leaderIdx].OpKnown("post-bad"); ok {
		t.Fatal("failed operation must not enter durable op-ID state")
	}

	// The leader's adapter rejects new authoritative mutations.
	if _, err := h.adapters[leaderIdx].CreatePost(context.Background(), "p2", mkPost("host-b", "host")); err == nil {
		t.Fatal("unhealthy leader must reject new authoritative mutations")
	}

	// The committed operation is retained on a healthy follower (the client
	// must not assume "nothing happened").
	followerIdx := 0
	for followerIdx = 0; followerIdx < 3; followerIdx++ {
		if followerIdx != leaderIdx {
			break
		}
	}
	waitForCount(t, h.dbs[followerIdx], `SELECT COUNT(*) FROM posts WHERE id='p1'`, 1)
}
