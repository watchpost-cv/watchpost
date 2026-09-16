// Package runtime composes the production replicated stack for a configured
// Watchpost node and drives runtime readiness from the actual raft lifecycle.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"

	"github.com/watchpost-cv/watchpost/internal/cluster"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/store"
)

// DefaultProposePath is the authenticated leader proposal RPC endpoint on the
// cluster peer API (must match server.ReplicatedProposePath).
const DefaultProposePath = "/api/cluster/v1/replication/propose"

// Options configures the production replicated composition of a node.
type Options struct {
	Logger      *slog.Logger
	Database    *store.Store // product DB (posts/rules + cluster_identity/cluster_members/cluster_nonces)
	NodeID      string       // raft node ID; defaults to the cluster identity node_id
	Address     string       // raft replication address (default 127.0.0.1:0)
	Bootstrap   bool         // single-node bootstrap (explicit raft membership operation)
	Transport   *cluster.Transport
	ProposePath string
	SnapshotDir string
	// ReadinessInterval is the readiness derivation cadence (default 150ms). It
	// exists as a test seam; production uses the default.
	ReadinessInterval time.Duration
}

func (o Options) proposePath() string {
	if o.ProposePath != "" {
		return o.ProposePath
	}
	return DefaultProposePath
}

// Replicated is the production replicated composition of a configured node.
// Readiness is driven by the actual raft lifecycle; Close() performs the
// shutdown/drain ordering (reject new -> node shutdown -> transport close).
type Replicated struct {
	Controller *replicated.Controller
	Node       *replication.Node
	Net        *replication.NetTransport
	FSM        *replicated.FSM
	Adapter    *replicated.Adapter
	done       chan struct{}
	stop       context.CancelFunc
	closeOnce  sync.Once
}

// New composes the production replicated stack: product FSM ->
// WatchpostAuthenticator -> NetTransport -> raft Node -> Adapter -> Controller
// (ModeReplicated, ReadinessStarting) with the production ForwardClient. It
// does NOT promote readiness: the driver derives readiness from raft state,
// so HTTP mutations are rejected until the node is actually caught up and a
// usable leader exists.
func New(ctx context.Context, o Options) (*Replicated, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Database == nil {
		return nil, errors.New("runtime: database required")
	}
	if o.NodeID == "" {
		var id string
		if err := o.Database.DB.QueryRow(`SELECT node_id FROM cluster_identity WHERE singleton=1`).Scan(&id); err != nil {
			return nil, fmt.Errorf("runtime: replication node id: %w", err)
		}
		o.NodeID = id
	}
	if o.Address == "" {
		o.Address = "127.0.0.1:0"
	}
	if o.SnapshotDir == "" {
		dir, err := os.MkdirTemp("", "watchpost-raft-snapshots")
		if err != nil {
			return nil, err
		}
		o.SnapshotDir = dir
	}
	if o.ReadinessInterval <= 0 {
		o.ReadinessInterval = 150 * time.Millisecond
	}

	fsm, err := replicated.NewFSM(o.Database.DB)
	if err != nil {
		return nil, fmt.Errorf("runtime: replication fsm: %w", err)
	}
	auth := replicated.NewWatchpostAuthenticator(o.Database.DB, replication.Version)
	caps := replication.Capabilities{
		ID:                      raft.ServerID(o.NodeID),
		OperationSchemaVersions: []int{1, replication.Version},
		SnapshotFormatVersions:  []int{replication.SnapshotFormatVersion},
	}
	nt, err := replication.NewNetTransport(replication.NetTransportOptions{
		ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Authenticator: auth, Membership: auth, PeerCredentials: auth,
		Protocol: replication.Version, Capabilities: caps, RevalidateEvery: time.Hour, InsecureAllowPlaintext: true,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: replication transport: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStore(filepath.Join(o.SnapshotDir, "snapshots"), 3, nil)
	if err != nil {
		_ = nt.Close()
		return nil, fmt.Errorf("runtime: snapshot store: %w", err)
	}
	node, err := replication.NewNode(replication.NodeOptions{
		ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(nt.LocalAddr()), Transport: nt,
		LogStore: raft.NewInmemStore(), StableStore: raft.NewInmemStore(), SnapshotStore: snaps,
		FSM: fsm, Bootstrap: o.Bootstrap, CapabilitySource: auth,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		_ = nt.Close()
		return nil, fmt.Errorf("runtime: raft node: %w", err)
	}
	adapter := replicated.NewAdapter(node, fsm, o.Database.DB, "watchpost")
	ctrl := replicated.NewController(adapter)
	ctrl.SetMode(replicated.ModeReplicated)
	ctrl.SetReadiness(replicated.ReadinessStarting)
	ctrl.SetForwardClient(productionForwardClient(o.Transport, node, o.proposePath()))

	ctx, stop := context.WithCancel(ctx)
	r := &Replicated{Controller: ctrl, Node: node, Net: nt, FSM: fsm, Adapter: adapter, done: make(chan struct{}), stop: stop}
	go r.driveReadiness(ctx, o.ReadinessInterval)
	return r, nil
}

// driveReadiness derives runtime readiness from the actual raft lifecycle:
// starting -> learner/caught-up -> ready-follower -> ready-leader -> no-leader
// and shutting-down. It never promotes merely because the raft process exists.
func (r *Replicated) driveReadiness(ctx context.Context, interval time.Duration) {
	defer close(r.done)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Controller.SetReadiness(replicated.ReadinessShuttingDown)
			return
		case <-tick.C:
		}
		switch r.Node.State() {
		case raft.Leader:
			r.Controller.SetReadiness(replicated.ReadinessReadyLeader)
		case raft.Follower:
			addr, _ := r.Node.Leader()
			switch {
			case addr != "" && r.caughtUp():
				r.Controller.SetReadiness(replicated.ReadinessReadyFollower)
			case addr != "":
				r.Controller.SetReadiness(replicated.ReadinessLearner)
			default:
				r.Controller.SetReadiness(replicated.ReadinessNoLeader)
			}
		case raft.Candidate:
			r.Controller.SetReadiness(replicated.ReadinessNoLeader)
		case raft.Shutdown:
			r.Controller.SetReadiness(replicated.ReadinessShuttingDown)
		}
	}
}

// caughtUp reports whether the follower has processed its entire raft log
// (raft's own applied index reached its last log index; config changes and
// no-ops count here, unlike the product FSM's applied index) and has recent
// leader contact.
func (r *Replicated) caughtUp() bool {
	stats := r.Node.Stats()
	applied := parseIndex(stats["applied_index"])
	last := parseIndex(stats["last_log_index"])
	if applied < last {
		return false
	}
	// raft Stats reports "last_contact" as "0" for a leader, "never" when no
	// contact, or the duration string since the last leader contact.
	switch contact := stats["last_contact"]; contact {
	case "0":
		return true
	case "", "never":
		return false
	default:
		d, err := time.ParseDuration(contact)
		if err != nil {
			return false
		}
		return d < 2*time.Second
	}
}

func parseIndex(v string) uint64 {
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

// Close performs the shutdown ordering: readiness shutting-down (reject new
// mutations), drain of the driver, raft node shutdown, then transport close.
// The store close remains the caller's responsibility and happens last.
func (r *Replicated) Close() {
	r.closeOnce.Do(func() {
		r.Controller.SetReadiness(replicated.ReadinessShuttingDown)
		r.stop()
		<-r.done
		_ = r.Node.Shutdown()
		_ = r.Net.Close()
	})
}

// productionForwardClient forwards a ready follower's mutation over the
// authenticated Gantry cluster RPC to the current raft leader's proposal
// endpoint, preserving the operation identity for durable retry idempotency.
func productionForwardClient(t *cluster.Transport, node *replication.Node, path string) replicated.ForwardClient {
	return func(ctx context.Context, fr replicated.ForwardRequest) (*replication.ApplyResult, error) {
		if t == nil {
			return nil, errors.New("replication: forward transport unavailable")
		}
		_, leaderID := node.Leader()
		if leaderID == "" {
			return nil, errors.New("replication: no leader to forward to")
		}
		body, err := json.Marshal(fr)
		if err != nil {
			return nil, err
		}
		resp, err := t.Do(ctx, string(leaderID), http.MethodPost, path, "replication", body)
		if err != nil {
			return nil, fmt.Errorf("replication forward: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return nil, fmt.Errorf("replication forward rejected (%d): %s", resp.StatusCode, b)
		}
		var ar replication.ApplyResult
		if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
			return nil, err
		}
		return &ar, nil
	}
}
