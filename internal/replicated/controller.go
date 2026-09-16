package replicated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
)

// ForwardRequest is the authenticated application-layer forwarding payload: the
// semantic mutation intent (never a pre-built operation carrying a remote
// dependency-graph revision). The leader reconstructs the operation through its
// own adapter, capturing its own graph revision and validating against its own
// applied state.
type ForwardRequest struct {
	Kind     string          `json:"kind"`
	ObjectID string          `json:"object_id"`
	OpID     string          `json:"op_id"`
	Revision int64           `json:"revision,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// ForwardClient is the authenticated Gantry application-RPC forwarding
// transport from a ready follower to the current leader. The live wiring
// installs it; the deterministic harness routes to the leader's controller.
type ForwardClient func(ctx context.Context, req ForwardRequest) (*replication.ApplyResult, error)

// Mode is the configured operating mode of a Watchpost node.
type Mode int

const (
	ModeStandalone Mode = iota
	ModeReplicated
)

func (m Mode) String() string {
	if m == ModeReplicated {
		return "replicated"
	}
	return "standalone"
}

// Readiness is the runtime replicated-readiness of a node. It is deliberately
// distinct from the configured mode: a configured replicated node that is not
// ReadyLeader/ReadyFollower MUST reject authoritative mutations (never fail
// open to local SQL).
type Readiness int

const (
	ReadinessStarting Readiness = iota
	ReadinessLearner
	ReadinessReadyFollower
	ReadinessReadyLeader
	ReadinessNoLeader
	ReadinessUnhealthy
	ReadinessShuttingDown
)

func (r Readiness) String() string {
	switch r {
	case ReadinessStarting:
		return "starting"
	case ReadinessLearner:
		return "learner/catching-up"
	case ReadinessReadyFollower:
		return "ready-follower"
	case ReadinessReadyLeader:
		return "ready-leader"
	case ReadinessNoLeader:
		return "no-leader"
	case ReadinessUnhealthy:
		return "unhealthy"
	case ReadinessShuttingDown:
		return "shutting-down"
	}
	return "unknown"
}

// ErrStandalonePath is returned when a replicated router is consulted while the
// node is configured standalone: the caller must use the existing local domain
// mutation path instead.
var ErrStandalonePath = errors.New("replicated router: configured standalone; use the existing local mutation path")

// Controller owns the configured operating mode, the runtime replicated
// readiness and the authoritative mutation authority (the Adapter). It is the
// single product-level gate that guarantees a configured replicated node never
// falls back to direct local SQL when replication is unavailable.
type Controller struct {
	mu             sync.Mutex
	mode           Mode
	readiness      Readiness
	adapter        *Adapter
	leaderResolver func() *Adapter
	forwardClient  ForwardClient
}

// NewController returns a mutation authority over adapter. It starts as
// configured standalone at readiness starting; the production wiring sets the
// mode and drives readiness through the startup/shutdown ordering.
func NewController(adapter *Adapter) *Controller {
	return &Controller{adapter: adapter, mode: ModeStandalone, readiness: ReadinessStarting}
}

// SetMode sets the configured operating mode.
func (c *Controller) SetMode(m Mode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mode = m
}

// SetReadiness sets the runtime replicated readiness.
func (c *Controller) SetReadiness(r Readiness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readiness = r
}

// SetLeaderResolver installs the resolver that returns the current leader's
// Adapter (the deterministic harness fallback for ready-follower forwarding).
// The live service installs a ForwardClient instead.
func (c *Controller) SetLeaderResolver(fn func() *Adapter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaderResolver = fn
}

// SetForwardClient installs the authenticated Gantry application-RPC forwarding
// transport used by ready-follower mutations. When installed it takes
// precedence over the in-process leader resolver.
func (c *Controller) SetForwardClient(fn ForwardClient) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forwardClient = fn
}

// State returns the configured mode and runtime readiness.
func (c *Controller) State() (Mode, Readiness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode, c.readiness
}

// Adapter returns the authoritative mutation authority.
func (c *Controller) Adapter() *Adapter {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adapter
}

// opID returns a fresh operation identity for a distinct semantic mutation
// intent. The live caller supplies its own request identity (idempotency key);
// absent that plumbing this is the per-intent identity the durable layer keys
// retry deduplication on.
func (c *Controller) opID(prefix string) string {
	c.mu.Lock()
	adapter := c.adapter
	c.mu.Unlock()
	if adapter == nil {
		return prefix + "-local"
	}
	return adapter.opID(prefix)
}

// awaitLocalApplied blocks until the local FSM has applied at least index (the
// forwarded operation's commit index) or the context is done, so a follower
// only returns a forwarded mutation once its own applied state reflects it.
func (c *Controller) awaitLocalApplied(ctx context.Context, index uint64) error {
	c.mu.Lock()
	adapter := c.adapter
	c.mu.Unlock()
	if adapter == nil {
		return nil
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		applied, _ := adapter.AppliedIndex()
		if applied >= index {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// MutationAuthority is the authoritative replicated mutation choke point that
// the posts/rules domain services consult. It returns ErrStandalonePath when
// the node is configured standalone (the caller then performs its existing
// local transaction); otherwise it routes to the leader proposal or rejects.
type MutationAuthority interface {
	CreatePost(ctx context.Context, id string, p PostPayload) (*replication.ApplyResult, error)
	UpdatePost(ctx context.Context, id string, expectedVersion int64, p PostPayload) (*replication.ApplyResult, error)
	DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error)
	AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error)
	CreateRule(ctx context.Context, id string, r RulePayload) (*replication.ApplyResult, error)
	SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error)
}

// Router is the authoritative replicated mutation choke point for the
// posts/post_dependencies/rules services. It enforces the mutation-readiness
// matrix: standalone -> local path (sentinel); ready leader -> propose; ready
// follower -> forward to the leader; any other replicated readiness -> reject.
// It NEVER falls back to local SQL for a configured replicated node.
type Router struct{ c *Controller }

var _ MutationAuthority = (*Router)(nil)

// NewRouter returns a mutation router over ctrl.
func NewRouter(ctrl *Controller) *Router { return &Router{c: ctrl} }

// CreatePost routes a post create.
func (r *Router) CreatePost(ctx context.Context, id string, p PostPayload) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindPostCreate, ObjectID: id, OpID: r.c.opID("post"), Payload: mustJSON(p)}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) { return a.CreatePost(ctx, id, p) })
}

// UpdatePost routes a post update.
func (r *Router) UpdatePost(ctx context.Context, id string, expectedVersion int64, p PostPayload) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindPostUpdate, ObjectID: id, OpID: r.c.opID("post"), Revision: expectedVersion, Payload: mustJSON(p)}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) { return a.UpdatePost(ctx, id, expectedVersion, p) })
}

// DeletePost routes a post delete.
func (r *Router) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindPostDelete, ObjectID: id, OpID: r.c.opID("post")}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) { return a.DeletePost(ctx, id) })
}

// AddDependency routes a dependency add.
func (r *Router) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindDependencyAdd, ObjectID: source, OpID: r.c.opID("dep"), Payload: mustJSON(depPayload{DependsOn: depends})}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) { return a.AddDependency(ctx, source, depends) })
}

// CreateRule routes a rule create.
func (r *Router) CreateRule(ctx context.Context, id string, rl RulePayload) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindRuleCreate, ObjectID: id, OpID: r.c.opID("rule"), Payload: mustJSON(rl)}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) { return a.CreateRule(ctx, id, rl) })
}

// SetRuleEnabled routes a rule enable/disable.
func (r *Router) SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindRuleSetEnable, ObjectID: id, OpID: r.c.opID("rule"), Revision: expectedVersion, Payload: mustJSON(RulePayload{Enabled: enabled})}
	return r.route(ctx, fr, func(a *Adapter) (*replication.ApplyResult, error) {
		return a.SetRuleEnabled(ctx, id, expectedVersion, enabled)
	})
}

// route applies the mutation authority matrix.
func (r *Router) route(ctx context.Context, fr ForwardRequest, fn func(*Adapter) (*replication.ApplyResult, error)) (*replication.ApplyResult, error) {
	c := r.c
	c.mu.Lock()
	mode, rd, adapter, resolver, fwd := c.mode, c.readiness, c.adapter, c.leaderResolver, c.forwardClient
	c.mu.Unlock()

	if mode == ModeStandalone {
		return nil, ErrStandalonePath
	}
	switch rd {
	case ReadinessReadyLeader:
		return fn(adapter)
	case ReadinessReadyFollower:
		if fwd != nil {
			res, err := fwd(ctx, fr)
			if err != nil {
				return nil, err
			}
			if res != nil {
				if err := c.awaitLocalApplied(ctx, res.Index); err != nil {
					return nil, err
				}
			}
			return res, nil
		}
		if resolver == nil || resolver() == nil {
			return nil, fmt.Errorf("replicated mutation unavailable: no leader to forward to")
		}
		return fn(resolver())
	default:
		return nil, fmt.Errorf("replicated mutation unavailable (readiness %s)", rd)
	}
}

// LeaderProposeHandler is the authenticated leader-side proposal endpoint for
// the Gantry application RPC. authenticate verifies the inbound peer request
// (the live wiring uses the existing cluster transport's Authenticate); the
// forwarded mutation intent is then routed through the leader's own adapter
// (its own dependency-graph revision and applied-state validation).
func (c *Controller) LeaderProposeHandler(authenticate func(r *http.Request) (string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := authenticate(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var fr ForwardRequest
		if err := json.Unmarshal(body, &fr); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		mode, rd, adapter := c.mode, c.readiness, c.adapter
		c.mu.Unlock()
		if mode != ModeReplicated || rd != ReadinessReadyLeader {
			http.Error(w, "leader not ready", http.StatusServiceUnavailable)
			return
		}
		res, err := applyForwarded(adapter, fr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})
}

// applyForwarded routes a forwarded mutation intent through the leader's own
// adapter, preserving the follower's operation identity so the durable
// operation-ID contract provides retry idempotency and same-ID/different-payload
// fail-closed behaviour.
func applyForwarded(a *Adapter, fr ForwardRequest) (*replication.ApplyResult, error) {
	switch fr.Kind {
	case KindPostCreate:
		var p PostPayload
		if err := json.Unmarshal(fr.Payload, &p); err != nil {
			return nil, err
		}
		return a.CreatePostWithOp(context.Background(), fr.ObjectID, fr.OpID, p)
	case KindPostUpdate:
		var p PostPayload
		if err := json.Unmarshal(fr.Payload, &p); err != nil {
			return nil, err
		}
		return a.UpdatePostWithOp(context.Background(), fr.ObjectID, fr.OpID, fr.Revision, p)
	case KindPostDelete:
		return a.DeletePostWithOp(context.Background(), fr.ObjectID, fr.OpID)
	case KindDependencyAdd:
		var d depPayload
		if err := json.Unmarshal(fr.Payload, &d); err != nil {
			return nil, err
		}
		return a.AddDependencyWithOp(context.Background(), fr.ObjectID, fr.OpID, d.DependsOn)
	case KindRuleCreate:
		var p RulePayload
		if err := json.Unmarshal(fr.Payload, &p); err != nil {
			return nil, err
		}
		return a.CreateRuleWithOp(context.Background(), fr.ObjectID, fr.OpID, p)
	case KindRuleSetEnable:
		var p RulePayload
		if err := json.Unmarshal(fr.Payload, &p); err != nil {
			return nil, err
		}
		return a.SetRuleEnabledWithOp(context.Background(), fr.ObjectID, fr.OpID, fr.Revision, p.Enabled)
	default:
		return nil, fmt.Errorf("unsupported forwarded kind %q", fr.Kind)
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
