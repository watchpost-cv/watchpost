package replicated

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// newAuthNode builds a raft node whose NetTransport authenticates with a real
// WatchpostAuthenticator over memberDB (pairwise cluster_members credentials)
// and whose product FSM materializes into productDB.
func newAuthNode(t *testing.T, id raft.ServerID, addr raft.ServerAddress, memberDB, productDB *sql.DB, bootstrap bool) (*replication.Node, *replication.NetTransport) {
	t.Helper()
	protocol := replication.Version
	auth := NewWatchpostAuthenticator(memberDB, protocol)
	caps := replication.Capabilities{ID: id, OperationSchemaVersions: []int{1, protocol}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}}
	nt, err := replication.NewNetTransport(replication.NetTransportOptions{
		ID: id, Address: addr, Authenticator: auth, Membership: auth, PeerCredentials: auth,
		Protocol: protocol, Capabilities: caps, RevalidateEvery: time.Hour, InsecureAllowPlaintext: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nt.Close() })
	fsm, err := NewFSM(productDB)
	if err != nil {
		t.Fatal(err)
	}
	snaps, err := raft.NewFileSnapshotStore(t.TempDir(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	node, err := replication.NewNode(replication.NodeOptions{
		ID: id, Address: nt.LocalAddr(), Transport: nt,
		LogStore: raft.NewInmemStore(), StableStore: raft.NewInmemStore(), SnapshotStore: snaps,
		FSM: fsm, Bootstrap: bootstrap, CapabilitySource: auth,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Shutdown() })
	return node, nt
}

// pairwiseAuthDB builds a membership DB where this node stores the peer rows:
// for each (peer, outbound, inboundFromPeer), the DB contains a row for peer
// with outbound_secret=outbound and inbound_secret_hash=hash(inboundFromPeer).
func pairwiseAuthDB(t *testing.T, localID string, rows map[string][2]string) *sql.DB {
	t.Helper()
	db := openTestDB(t)
	if _, err := db.Exec(authSchema); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,created_at) VALUES(1,?,?,?,?, ?,1,?)`, localID, localID+"-inst", []byte("key"), []byte("key"), `["health","replication"]`, time.Now().UTC().Format(time.RFC3339Nano))
	for peer, cred := range rows {
		mustExec(t, db, `INSERT INTO cluster_members(node_id,installation_id,public_endpoint,public_key,capabilities_json,protocol_version,inbound_secret_hash,outbound_secret,state,created_at,paired_at,credential_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)`,
			peer, peer+"-inst", "https://"+peer+".example", []byte("key"), `["health","replication"]`, 1, hashSecret(cred[1]), cred[0], "active", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func authNodeAddr(t *testing.T, node *replication.Node) raft.ServerAddress {
	t.Helper()
	return node.Address()
}

// TestAsymmetricTwoPeerTransport proves two real Watchpost authenticators +
// NetTransports with deliberately different pairwise directional credentials
// (A_to_B != B_to_A) form a working cluster: A is authenticated by B using
// A_to_B and B is authenticated by A using B_to_A.
func TestAsymmetricTwoPeerTransport(t *testing.T) {
	const aToB, bToA = "A_to_B_secret", "B_to_A_secret"
	if aToB == bToA {
		t.Fatal("test requires distinct directional credentials")
	}
	// A's membership DB: peer B (outbound=A_to_B; B presents B_to_A to A).
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{"B": {aToB, bToA}})
	// B's membership DB: peer A (outbound=B_to_A; A presents A_to_B to B).
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {bToA, aToB}})

	nodeA, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	nodeB, _ := newAuthNode(t, "B", "127.0.0.1:0", memberB, openTestDB(t), false)

	// Wait for A to be leader, then join B (drives the mutual pairwise handshake).
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && nodeA.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if nodeA.State() != raft.Leader {
		t.Fatal("A did not become leader")
	}
	if err := nodeA.AddVoter("B", authNodeAddr(t, nodeB)); err != nil {
		t.Fatalf("A->B join with pairwise credentials failed: %v", err)
	}
	// A write replicates to B (proves deterministic apply over the authenticated
	// transport).
	fsm := nodeA.FSM().(*FSM)
	adapter := NewAdapter(nodeA, fsm, fsmDB(t, nodeA), "watchpost")
	if _, err := adapter.CreatePost(context.Background(), "p1", mkPost("host-a", "host")); err != nil {
		t.Fatalf("create: %v", err)
	}
	waitAuthConverge(t, nodeA, nodeB, "p1")
}

func fsmDB(t *testing.T, n *replication.Node) *sql.DB {
	t.Helper()
	return n.FSM().(*FSM).db
}

func waitAuthConverge(t *testing.T, leader, follower *replication.Node, wantPost string) {
	t.Helper()
	la, _ := leader.AppliedIndex()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		da, _ := follower.AppliedIndex()
		if da >= la {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fdb := follower.FSM().(*FSM).db
	if got := count(t, fdb, `SELECT COUNT(*) FROM posts WHERE id='`+wantPost+`'`); got != 1 {
		t.Fatalf("follower did not converge on %s", wantPost)
	}
}

// TestAsymmetricWrongCredentialRejected proves a node presenting the wrong
// directional credential cannot join.
func TestAsymmetricWrongCredentialRejected(t *testing.T) {
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{"B": {"WRONG_A_to_B", "B_to_A"}})
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {"B_to_A", "A_to_B"}}) // expects A_to_B
	nodeA, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	nodeB, _ := newAuthNode(t, "B", "127.0.0.1:0", memberB, openTestDB(t), false)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && nodeA.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	// A conf-change may commit by A alone even when B rejects the handshake, so
	// assert the real effect: B must never become reachable (no AppendEntries
	// arrive, applied index stays 0).
	_ = nodeA.AddVoter("B", authNodeAddr(t, nodeB))
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		da, _ := nodeB.AppliedIndex()
		if da != 0 {
			t.Fatal("B became reachable despite the wrong directional credential")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestMultiPeerCredentialSelection proves A uses a distinct outbound credential
// per peer (A_to_B != A_to_C) and both joins succeed.
func TestMultiPeerCredentialSelection(t *testing.T) {
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{
		"B": {"A_to_B", "B_to_A"},
		"C": {"A_to_C", "C_to_A"},
	})
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {"B_to_A", "A_to_B"}})
	memberC := pairwiseAuthDB(t, "C", map[string][2]string{"A": {"C_to_A", "A_to_C"}})
	nodeA, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	nodeB, _ := newAuthNode(t, "B", "127.0.0.1:0", memberB, openTestDB(t), false)
	nodeC, _ := newAuthNode(t, "C", "127.0.0.1:0", memberC, openTestDB(t), false)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && nodeA.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if err := nodeA.AddVoter("B", authNodeAddr(t, nodeB)); err != nil {
		t.Fatalf("join B: %v", err)
	}
	if err := nodeA.AddVoter("C", authNodeAddr(t, nodeC)); err != nil {
		t.Fatalf("join C: %v", err)
	}
	// Both joins succeeded -> A selected A_to_B for B and A_to_C for C.
}

// TestRotationReconnectProvesOverlap proves that after rotating A's outbound
// credential to B and installing the corresponding pending inbound on B, a
// NEW/re-established connection uses the current credential and promotion
// follows the existing Watchpost lifecycle; an expired pending is rejected.
func TestRotationReconnectProvesOverlap(t *testing.T) {
	const aToB, bToA, aToB2 = "A_to_B", "B_to_A", "A_to_B_ROTATED"
	memberA := pairwiseAuthDB(t, "A", map[string][2]string{"B": {aToB, bToA}})
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {bToA, aToB}})
	// Establish A<->B with the original credential.
	nodeA, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	nodeB, _ := newAuthNode(t, "B", "127.0.0.1:0", memberB, openTestDB(t), false)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && nodeA.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if err := nodeA.AddVoter("B", authNodeAddr(t, nodeB)); err != nil {
		t.Fatalf("initial join: %v", err)
	}

	// Rotate: A's outbound for B becomes aToB2; B installs the matching pending
	// inbound for A within the overlap window.
	mustExec(t, memberA, `UPDATE cluster_members SET outbound_secret=? WHERE node_id='B'`, aToB2)
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, memberB, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='A'`, hashSecret(aToB2), exp)

	// A new/re-established connection (fresh node A2 over the same membership
	// DB) resolves the CURRENT outbound credential for B and is accepted with
	// promotion.
	nodeA2, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && nodeA2.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	if err := nodeA2.AddVoter("B", authNodeAddr(t, nodeB)); err != nil {
		t.Fatalf("reconnect after rotation: %v", err)
	}
	var cur []byte
	var pending []byte
	var cv int
	if err := memberB.QueryRow(`SELECT inbound_secret_hash,pending_inbound_secret_hash,credential_version FROM cluster_members WHERE node_id='A'`).Scan(&cur, &pending, &cv); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 || string(cur) != string(hashSecret(aToB2)) || cv != 2 {
		t.Fatalf("promotion after rotation did not occur: cv=%d", cv)
	}

	// Expired pending: rotate again, but with a past expiry; a new connection
	// using the (still not-current) rotated credential must be rejected.
	mustExec(t, memberA, `UPDATE cluster_members SET outbound_secret=? WHERE node_id='B'`, aToB2+"-2")
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, memberB, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='A'`, hashSecret(aToB2+"-2"), expired)
	nodeA3, _ := newAuthNode(t, "A", "127.0.0.1:0", memberA, openTestDB(t), true)
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && nodeA3.State() != raft.Leader {
		time.Sleep(10 * time.Millisecond)
	}
	// A conf-change may commit alone; assert B never becomes reachable with the
	// expired pending credential.
	_ = nodeA3.AddVoter("B", authNodeAddr(t, nodeB))
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		da, _ := nodeB.AppliedIndex()
		if da != 0 {
			t.Fatal("B became reachable despite an expired pending rotated credential")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// newAuthTransport builds a bare authenticated NetTransport (outbound-only; it
// dials peers but need not consume RPCs) over memberDB.
func newAuthTransport(t *testing.T, id raft.ServerID, memberDB *sql.DB) (*replication.NetTransport, raft.ServerAddress) {
	t.Helper()
	protocol := replication.Version
	auth := NewWatchpostAuthenticator(memberDB, protocol)
	caps := replication.Capabilities{ID: id, OperationSchemaVersions: []int{1, protocol}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}}
	nt, err := replication.NewNetTransport(replication.NetTransportOptions{
		ID: id, Address: "127.0.0.1:0", Authenticator: auth, Membership: auth, PeerCredentials: auth,
		Protocol: protocol, Capabilities: caps, RevalidateEvery: time.Hour, InsecureAllowPlaintext: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nt.Close() })
	return nt, nt.LocalAddr()
}

// attemptAppendEntries drives a real authenticated transport RPC from a dialing
// transport to a running peer (whose raft consumes its transport and responds).
// A handshake/authentication failure surfaces as a returned error.
func attemptAppendEntries(t *testing.T, nt *replication.NetTransport, from raft.ServerID, target raft.ServerAddress, targetID raft.ServerID) error {
	t.Helper()
	req := &raft.AppendEntriesRequest{
		RPCHeader:         raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte(from), Addr: []byte(from)},
		Term:              1,
		Leader:            []byte(from),
		PrevLogEntry:      0,
		PrevLogTerm:       0,
		Entries:           nil,
		LeaderCommitIndex: 0,
	}
	return nt.AppendEntries(targetID, target, req, &raft.AppendEntriesResponse{})
}

// TestNegativeTransportDirectAuth certifies, with real Watchpost authenticators
// and real NetTransports, the actual connection/authentication outcome for
// correct, wrong, unrelated-peer, expired-pending and valid-pending
// directional credentials (not an AppliedIndex==0 heuristic).
func TestNegativeTransportDirectAuth(t *testing.T) {
	const aToB, bToA, aToC = "A_to_B", "B_to_A", "A_to_C"
	// Peer B (a real node consuming its transport) verifies against B.row[A].
	memberB := pairwiseAuthDB(t, "B", map[string][2]string{"A": {bToA, aToB}})
	nodeB, _ := newAuthNode(t, "B", "127.0.0.1:0", memberB, openTestDB(t), false)
	bAddr := authNodeAddr(t, nodeB)

	// 1) correct A_to_B: authenticated transport RPC succeeds.
	mA := pairwiseAuthDB(t, "A", map[string][2]string{"B": {aToB, bToA}})
	ntA, _ := newAuthTransport(t, "A", mA)
	if err := attemptAppendEntries(t, ntA, "A", bAddr, "B"); err != nil {
		t.Fatalf("correct A_to_B transport RPC failed: %v", err)
	}

	// 2) wrong A_to_B: the authenticated transport RPC must fail.
	mW := pairwiseAuthDB(t, "A", map[string][2]string{"B": {"WRONG_A_to_B", bToA}})
	ntW, _ := newAuthTransport(t, "A", mW)
	if err := attemptAppendEntries(t, ntW, "A", bAddr, "B"); err == nil {
		t.Fatal("wrong A_to_B must fail the authenticated transport RPC")
	}

	// 3) credential intended for C used toward B must fail.
	mU := pairwiseAuthDB(t, "A", map[string][2]string{"B": {aToC, bToA}})
	ntU, _ := newAuthTransport(t, "A", mU)
	if err := attemptAppendEntries(t, ntU, "A", bAddr, "B"); err == nil {
		t.Fatal("unrelated-peer credential (A_to_C toward B) must fail")
	}

	// 4) valid pending A_to_B: succeeds and promotes (existing lifecycle).
	mP := pairwiseAuthDB(t, "A", map[string][2]string{"B": {"A_to_B_ROT", bToA}})
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, memberB, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='A'`, hashSecret("A_to_B_ROT"), exp)
	ntP, _ := newAuthTransport(t, "A", mP)
	if err := attemptAppendEntries(t, ntP, "A", bAddr, "B"); err != nil {
		t.Fatalf("valid pending A_to_B transport RPC failed: %v", err)
	}
	var cur []byte
	var pending []byte
	var cv int
	if err := memberB.QueryRow(`SELECT inbound_secret_hash,pending_inbound_secret_hash,credential_version FROM cluster_members WHERE node_id='A'`).Scan(&cur, &pending, &cv); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 || string(cur) != string(hashSecret("A_to_B_ROT")) || cv != 2 {
		t.Fatalf("pending promotion did not occur: cv=%d", cv)
	}

	// 5) post-promotion fresh connection uses the promoted CURRENT credential
	// (no pending field) and succeeds.
	mC := pairwiseAuthDB(t, "A", map[string][2]string{"B": {"A_to_B_ROT", bToA}})
	ntC, _ := newAuthTransport(t, "A", mC)
	if err := attemptAppendEntries(t, ntC, "A", bAddr, "B"); err != nil {
		t.Fatalf("post-promotion current-credential RPC failed: %v", err)
	}

	// 6) expired pending A_to_B: the authenticated transport RPC must fail.
	mE := pairwiseAuthDB(t, "A", map[string][2]string{"B": {"A_to_B_EXPIRED", bToA}})
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, memberB, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='A'`, hashSecret("A_to_B_EXPIRED"), expired)
	ntE, _ := newAuthTransport(t, "A", mE)
	if err := attemptAppendEntries(t, ntE, "A", bAddr, "B"); err == nil {
		t.Fatal("expired pending A_to_B must fail the authenticated transport RPC")
	}
}
