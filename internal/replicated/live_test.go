package replicated

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// liveHarness composes the real production stack per node: WatchpostAuthenticator
// (pairwise cluster_members credentials), NetTransport, raft Node, product FSM,
// Adapter, Controller and Router - plus a shared adapter registry for leader
// resolution.
type liveHarness struct {
	t           *testing.T
	nodes       map[raft.ServerID]*replication.Node
	adapters    map[raft.ServerID]*Adapter
	controllers map[raft.ServerID]*Controller
	routers     map[raft.ServerID]*Router
}

func (h *liveHarness) leaderID() raft.ServerID {
	h.t.Helper()
	for id, n := range h.nodes {
		if n.State() == raft.Leader {
			return id
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for id, n := range h.nodes {
			if n.State() == raft.Leader {
				return id
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("no leader in live harness")
	return ""
}

func (h *liveHarness) converge() {
	h.t.Helper()
	la, _ := h.nodes[h.leaderID()].AppliedIndex()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
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
	h.t.Fatal("live harness nodes did not converge")
}

func (h *liveHarness) fsmDB(id raft.ServerID) *sql.DB { return h.nodes[id].FSM().(*FSM).db }

func newLiveCluster(t *testing.T) *liveHarness {
	t.Helper()
	const (
		aToB, bToA = "A_to_B", "B_to_A"
		aToC, cToA = "A_to_C", "C_to_A"
		bToC, cToB = "B_to_C", "C_to_B"
	)
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{"B": {aToB, bToA}, "C": {aToC, cToA}})
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {bToA, aToB}, "C": {bToC, cToB}})
	memberC := pairwiseAuthDB(t, "C", map[string][2]string{"A": {cToA, aToC}, "B": {cToB, bToC}})

	h := &liveHarness{
		t:           t,
		nodes:       map[raft.ServerID]*replication.Node{},
		adapters:    map[raft.ServerID]*Adapter{},
		controllers: map[raft.ServerID]*Controller{},
		routers:     map[raft.ServerID]*Router{},
	}
	ids := []raft.ServerID{"A", "B", "C"}
	members := map[raft.ServerID]*sql.DB{"A": memberA, "B": memberB, "C": memberC}
	for i, id := range ids {
		node, _ := newAuthNode(t, id, "127.0.0.1:0", members[id], openTestDB(t), i == 0)
		h.nodes[id] = node
	}
	// Join B and C as voters through the leader.
	li := h.leaderID()
	for _, id := range []raft.ServerID{"B", "C"} {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if err := h.nodes[li].AddVoter(id, authNodeAddr(t, h.nodes[id])); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// Per-node adapter + controller + router, with a shared leader resolver.
	for id, node := range h.nodes {
		fsm := node.FSM().(*FSM)
		h.adapters[id] = NewAdapter(node, fsm, fsm.db, "watchpost")
		h.controllers[id] = NewController(h.adapters[id])
		h.routers[id] = NewRouter(h.controllers[id])
	}
	for _, ctrl := range h.controllers {
		ctrl.SetLeaderResolver(func() *Adapter { return h.adapters[h.leaderID()] })
	}
	return h
}

// TestLiveLeaderMutation: a replicated ready leader mutates through the
// authoritative path and all nodes converge.
func TestLiveLeaderMutation(t *testing.T) {
	h := newLiveCluster(t)
	leader := h.leaderID()
	ctrl := h.controllers[leader]
	ctrl.SetMode(ModeReplicated)
	ctrl.SetReadiness(ReadinessReadyLeader)

	if _, err := h.routers[leader].CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatalf("leader mutation: %v", err)
	}
	h.converge()
	for id := range h.nodes {
		if got := count(t, h.fsmDB(id), `SELECT COUNT(*) FROM posts WHERE id='p1'`); got != 1 {
			t.Fatalf("node %s did not converge on p1", id)
		}
	}
}

// TestLiveFollowerForwarding: a replicated ready follower forwards the mutation
// to the current leader and all nodes converge.
func TestLiveFollowerForwarding(t *testing.T) {
	h := newLiveCluster(t)
	leader := h.leaderID()
	var follower raft.ServerID
	for id := range h.nodes {
		if id != leader {
			follower = id
			break
		}
	}
	h.controllers[leader].SetMode(ModeReplicated)
	h.controllers[leader].SetReadiness(ReadinessReadyLeader)
	h.controllers[follower].SetMode(ModeReplicated)
	h.controllers[follower].SetReadiness(ReadinessReadyFollower)

	if _, err := h.routers[follower].CreatePost(context.Background(), "pfwd", mkPost("host-f", "host")); err != nil {
		t.Fatalf("follower forwarded mutation: %v", err)
	}
	h.converge()
	for id := range h.nodes {
		if got := count(t, h.fsmDB(id), `SELECT COUNT(*) FROM posts WHERE id='pfwd'`); got != 1 {
			t.Fatalf("node %s did not converge on forwarded post", id)
		}
	}
}

// TestLiveRejectionMatrix: every non-ready replicated readiness rejects
// authoritative mutations without mutating any node.
func TestLiveRejectionMatrix(t *testing.T) {
	for _, rd := range []Readiness{ReadinessStarting, ReadinessLearner, ReadinessNoLeader, ReadinessUnhealthy, ReadinessShuttingDown} {
		t.Run(rd.String(), func(t *testing.T) {
			h := newLiveCluster(t)
			leader := h.leaderID()
			h.controllers[leader].SetMode(ModeReplicated)
			h.controllers[leader].SetReadiness(rd)
			if _, err := h.routers[leader].CreatePost(context.Background(), "reject", mkPost("host-r", "host")); err == nil {
				t.Fatal("mutation must be rejected at non-ready readiness")
			}
			for id := range h.nodes {
				if got := count(t, h.fsmDB(id), `SELECT COUNT(*) FROM posts WHERE id='reject'`); got != 0 {
					t.Fatalf("rejected mutation mutated node %s", id)
				}
			}
		})
	}
}

// TestLiveNoLocalFallback: the central CP7D-4b invariant - a configured
// replicated node never falls back to local SQL when replication becomes
// unavailable.
func TestLiveNoLocalFallback(t *testing.T) {
	h := newLiveCluster(t)
	leader := h.leaderID()
	ctrl := h.controllers[leader]
	ctrl.SetMode(ModeReplicated)
	ctrl.SetReadiness(ReadinessReadyLeader)
	if _, err := h.routers[leader].CreatePost(context.Background(), "before", mkPost("host-a", "host")); err != nil {
		t.Fatal(err)
	}
	h.converge()

	// Replication becomes unavailable (e.g. no leader).
	ctrl.SetReadiness(ReadinessNoLeader)
	if _, err := h.routers[leader].CreatePost(context.Background(), "after", mkPost("host-b", "host")); err == nil {
		t.Fatal("mutation must be rejected when replication is unavailable")
	}
	for id := range h.nodes {
		if got := count(t, h.fsmDB(id), `SELECT COUNT(*) FROM posts WHERE id='after'`); got != 0 {
			t.Fatalf("replicated node fell back to local SQL on node %s", id)
		}
		if got := count(t, h.fsmDB(id), `SELECT COUNT(*) FROM posts WHERE id='before'`); got != 1 {
			t.Fatalf("existing replicated state changed on node %s", id)
		}
	}
}

// TestLiveStandalonePath: a configured standalone node routes mutations to the
// existing local path (sentinel), not the replicated adapter.
func TestLiveStandalonePath(t *testing.T) {
	h := newLiveCluster(t)
	leader := h.leaderID()
	h.controllers[leader].SetMode(ModeStandalone)
	if _, err := h.routers[leader].CreatePost(context.Background(), "solo", mkPost("host-s", "host")); err != ErrStandalonePath {
		t.Fatalf("standalone router must return ErrStandalonePath, got %v", err)
	}
}

var _ = fmt.Sprintf
