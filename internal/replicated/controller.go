package replicated

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gantry-tools/gantry-core/replication"
)

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
// Adapter (used by ready-follower forwarding). In the live service this is the
// authenticated leader resolution path; in the harness it is the leader's
// adapter.
func (c *Controller) SetLeaderResolver(fn func() *Adapter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaderResolver = fn
}

// State returns the configured mode and runtime readiness.
func (c *Controller) State() (Mode, Readiness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode, c.readiness
}

// Router is the authoritative replicated mutation choke point for the
// posts/post_dependencies/rules services. It enforces the mutation-readiness
// matrix: standalone -> local path (sentinel); ready leader -> propose; ready
// follower -> forward to the leader; any other replicated readiness -> reject.
// It NEVER falls back to local SQL for a configured replicated node.
type Router struct{ c *Controller }

// NewRouter returns a mutation router over ctrl.
func NewRouter(ctrl *Controller) *Router { return &Router{c: ctrl} }

// CreatePost routes a post create.
func (r *Router) CreatePost(ctx context.Context, id string, p postPayload) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) { return a.CreatePost(ctx, id, p) })
}

// UpdatePost routes a post update.
func (r *Router) UpdatePost(ctx context.Context, id string, expectedVersion int64, p postPayload) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) { return a.UpdatePost(ctx, id, expectedVersion, p) })
}

// DeletePost routes a post delete.
func (r *Router) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) { return a.DeletePost(ctx, id) })
}

// AddDependency routes a dependency add.
func (r *Router) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) { return a.AddDependency(ctx, source, depends) })
}

// CreateRule routes a rule create.
func (r *Router) CreateRule(ctx context.Context, id string, rl rulePayload) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) { return a.CreateRule(ctx, id, rl) })
}

// SetRuleEnabled routes a rule enable/disable.
func (r *Router) SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	return r.route(ctx, func(a *Adapter) (*replication.ApplyResult, error) {
		return a.SetRuleEnabled(ctx, id, expectedVersion, enabled)
	})
}

// route applies the mutation authority matrix.
func (r *Router) route(ctx context.Context, fn func(*Adapter) (*replication.ApplyResult, error)) (*replication.ApplyResult, error) {
	c := r.c
	c.mu.Lock()
	mode, rd, adapter, resolver := c.mode, c.readiness, c.adapter, c.leaderResolver
	c.mu.Unlock()

	if mode == ModeStandalone {
		return nil, ErrStandalonePath
	}
	switch rd {
	case ReadinessReadyLeader:
		return fn(adapter)
	case ReadinessReadyFollower:
		if resolver == nil || resolver() == nil {
			return nil, fmt.Errorf("replicated mutation unavailable: no leader to forward to")
		}
		return fn(resolver())
	default:
		return nil, fmt.Errorf("replicated mutation unavailable (readiness %s)", rd)
	}
}
