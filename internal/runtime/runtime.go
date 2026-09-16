// Package runtime composes the production replicated stack for a configured
// Watchpost node and drives runtime readiness from the actual raft lifecycle.
package runtime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchpost-cv/watchpost/internal/config"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"

	"github.com/watchpost-cv/watchpost/internal/cluster"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/store"
)

// DefaultProposePath is the authenticated leader proposal RPC endpoint on the
// cluster peer API (must match server.ReplicatedProposePath).
const DefaultProposePath = "/api/cluster/v1/replication/propose"

// LoadReplicationTLS builds the production replication transport TLS config
// from the configured cert/key/CA triplet (mutual TLS contract: all three are
// required). Peer identity is bound by the mutual Gantry handshake over the
// encrypted channel - certificate verification provides channel trust, never
// identity - and the server additionally requires and verifies peer
// certificates against the configured cluster CA. An empty TLS configuration
// returns nil; the runtime then fails closed unless plaintext is explicitly
// opted in.
//
// InsecureSkipVerify is present on the shared client+server config because the
// NetTransport dials arbitrary peers with one config (no per-dial ServerName).
// The remote endpoint is authenticated by the mutual Gantry handshake
// (pairwise credential digest + signed handshake + nonce replay), so skipping
// TLS hostname verification does not weaken endpoint identity; it only leaves
// channel confidentiality/integrity to the TLS session.
// LoadReplicationTLS builds the production replication transport TLS config
// from the configured cert/key/CA triplet (the generic Core mutual-TLS helper).
func LoadReplicationTLS(cfg config.Config) (*tls.Config, error) {
	r := cfg.Replication
	return replication.LoadTLSConfig(r.TLSCert, r.TLSKey, r.TLSCA)
}

// Options configures the production replicated composition of a node.
type Options struct {
	Logger      *slog.Logger
	Database    *store.Store // product DB (posts/rules + cluster_identity/cluster_members/cluster_nonces)
	NodeID      string       // raft node ID; defaults to the cluster identity node_id
	DataDir     string       // Watchpost data dir: durable raft state lives under <DataDir>/replication/
	Address     string       // stable replication listen/advertise address (default 127.0.0.1:0)
	Bootstrap   bool         // single-node bootstrap (explicit raft membership operation)
	Transport   *cluster.Transport
	ProposePath string
	// TLSConfig is the production replication TLS (mutual). Required unless
	// InsecurePlaintext is explicitly opted in for local development.
	TLSConfig *tls.Config
	// InsecurePlaintext is an explicit local-development opt-in that disables
	// channel encryption. It is never the normal production path.
	InsecurePlaintext bool
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
// shutdown/drain ordering (reject new -> node shutdown -> raft store close ->
// transport close).
type Replicated struct {
	Controller *replicated.Controller
	Node       *replication.Node
	Net        *replication.NetTransport
	FSM        *replicated.FSM
	Adapter    *replicated.Adapter
	raftStore  *replication.BoltStore
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
	if o.DataDir == "" {
		return nil, errors.New("runtime: data directory required for durable raft state")
	}
	// Production invariant: the replication channel is encrypted unless the
	// operator explicitly opted into plaintext for local development.
	if o.TLSConfig == nil && !o.InsecurePlaintext {
		return nil, errors.New("runtime: replication TLS required (set Replication.TLSCert/TLSKey or explicitly opt into plaintext for local development)")
	}
	replicationDir := filepath.Join(o.DataDir, "replication")
	if err := osMkdirAll(replicationDir); err != nil {
		return nil, fmt.Errorf("runtime: replication dir: %w", err)
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
	// The authenticated cluster application-RPC transport (used by the follower
	// ForwardClient and distributed status) dials peer public endpoints over
	// HTTPS. Wire its HTTP client to trust the SAME cluster CA as the
	// replication transport, so the forward path trusts one cluster trust
	// domain rather than the default system roots.
	if o.Transport != nil && o.TLSConfig != nil && o.TLSConfig.RootCAs != nil {
		o.Transport.SetHTTPClient(&http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: o.TLSConfig.RootCAs, MinVersion: tls.VersionTLS12},
		}})
	}
	nt, err := replication.NewNetTransport(replication.NetTransportOptions{
		ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Authenticator: auth, Membership: auth, PeerCredentials: auth,
		TLSConfig: o.TLSConfig, Protocol: replication.Version, Capabilities: caps, RevalidateEvery: time.Hour,
		InsecureAllowPlaintext: o.InsecurePlaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: replication transport: %w", err)
	}
	// Durable raft state under <DataDir>/replication/: the bbolt log/stable
	// store and file snapshots. This is what makes the CP7D-3 recovery model
	// (persistent SQLite + persistent _replicated_meta + persistent raft log +
	// persistent snapshots) real across process restart.
	raftStore, err := replication.NewBoltStore(filepath.Join(replicationDir, "raft.db"))
	if err != nil {
		_ = nt.Close()
		return nil, fmt.Errorf("runtime: raft store: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStore(filepath.Join(replicationDir, "snapshots"), 3, nil)
	if err != nil {
		_ = raftStore.Close()
		_ = nt.Close()
		return nil, fmt.Errorf("runtime: snapshot store: %w", err)
	}
	node, err := replication.NewNode(replication.NodeOptions{
		ID: raft.ServerID(o.NodeID), Address: raft.ServerAddress(o.Address), Transport: nt,
		LogStore: raftStore, StableStore: raftStore, SnapshotStore: snaps,
		FSM: fsm, Bootstrap: o.Bootstrap, CapabilitySource: auth,
		HeartbeatTimeout: 250 * time.Millisecond, ElectionTimeout: 500 * time.Millisecond,
		CommitTimeout: 20 * time.Millisecond, LeaderLeaseTimeout: 250 * time.Millisecond,
		ProposeTimeout: 3 * time.Second,
	})
	if err != nil {
		_ = raftStore.Close()
		_ = nt.Close()
		return nil, fmt.Errorf("runtime: raft node: %w", err)
	}
	adapter := replicated.NewAdapter(node, fsm, o.Database.DB, "watchpost")
	ctrl := replicated.NewController(adapter)
	ctrl.SetMode(replicated.ModeReplicated)
	ctrl.SetReadiness(replicated.ReadinessStarting)
	ctrl.SetForwardClient(productionForwardClient(o.Transport, node, o.proposePath()))

	ctx, stop := context.WithCancel(ctx)
	r := &Replicated{Controller: ctrl, Node: node, Net: nt, FSM: fsm, Adapter: adapter, raftStore: raftStore, done: make(chan struct{}), stop: stop}
	go r.driveReadiness(ctx, o.ReadinessInterval)
	return r, nil
}

// driveReadiness runs the generic Core readiness driver over the real raft
// lifecycle with the product health hook (the FSM's committed-apply failure).
// It never promotes merely because the raft process exists.
func (r *Replicated) driveReadiness(ctx context.Context, interval time.Duration) {
	driver := replication.NewReadinessDriver(r.Node, func(rd replication.Readiness) {
		r.Controller.SetReadiness(rd)
	}, func() error { return r.FSM.ApplyFailure() }, interval)
	driver.Run(ctx)
	close(r.done)
}

func osMkdirAll(dir string) error { return os.MkdirAll(dir, 0o750) }

// Close performs the shutdown ordering: readiness shutting-down (reject new
// mutations), drain of the driver, raft node shutdown, then transport close.
// The store close remains the caller's responsibility and happens last.
func (r *Replicated) Close() {
	r.closeOnce.Do(func() {
		r.Controller.SetReadiness(replicated.ReadinessShuttingDown)
		r.stop()
		<-r.done
		_ = r.Node.Shutdown()
		_ = r.raftStore.Close()
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
