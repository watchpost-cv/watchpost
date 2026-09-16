package replicated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gantry-tools/gantry-core/replication"
)

// The configured-mode, runtime-readiness, forward envelope, request-identity
// propagation and the authoritative mutation routing matrix are generic
// Gantry Core replication primitives (replication.Authority). Watchpost aliases
// them here so the product surface is unchanged; the product-specific parts that
// remain are the mutation authority (Adapter) and the six posts/rules methods.

type Mode = replication.Mode

const (
	ModeStandalone = replication.ModeStandalone
	ModeReplicated = replication.ModeReplicated
)

type Readiness = replication.Readiness

const (
	ReadinessStarting      = replication.ReadinessStarting
	ReadinessLearner       = replication.ReadinessLearner
	ReadinessReadyFollower = replication.ReadinessReadyFollower
	ReadinessReadyLeader   = replication.ReadinessReadyLeader
	ReadinessNoLeader      = replication.ReadinessNoLeader
	ReadinessUnhealthy     = replication.ReadinessUnhealthy
	ReadinessShuttingDown  = replication.ReadinessShuttingDown
)

// ForwardRequest is the generic application-layer forwarding envelope (aliased
// from Core); the payload carries the product's semantic mutation intent.
type ForwardRequest = replication.ForwardRequest

// ForwardClient is the generic authenticated application-RPC forwarding
// transport (aliased from Core).
type ForwardClient = replication.ForwardClient

// ErrStandalonePath is returned when a replicated router is consulted while the
// node is configured standalone: the caller must use the existing local domain
// mutation path instead.
var ErrStandalonePath = replication.ErrStandalone

// WithRequestID attaches the caller-supplied idempotency/request identity to ctx
// (generic Core propagation).
func WithRequestID(ctx context.Context, id string) context.Context {
	return replication.WithRequestID(ctx, id)
}

// RequestID returns the caller-supplied idempotency/request identity, or ""
// when the caller provided none.
func RequestID(ctx context.Context) string {
	return replication.RequestID(ctx)
}

// Controller owns the configured operating mode, the runtime replicated
// readiness (via the generic Core Authority) and the authoritative product
// mutation authority (the Adapter). It is the single product-level gate that
// guarantees a configured replicated node never falls back to direct local SQL
// when replication is unavailable.
type Controller struct {
	auth           *replication.Authority
	adapter        *Adapter
	node           *replication.Node
	leaderResolver func() *Adapter
}

// NewController returns a mutation authority over adapter. It starts as
// configured standalone at readiness starting; the production wiring sets the
// mode and drives readiness through the startup/shutdown ordering.
func NewController(adapter *Adapter) *Controller {
	return &Controller{auth: replication.NewAuthority(), adapter: adapter, node: adapter.node}
}

// SetMode sets the configured operating mode.
func (c *Controller) SetMode(m Mode) { c.auth.SetMode(m) }

// SetReadiness sets the runtime replicated readiness.
func (c *Controller) SetReadiness(r Readiness) { c.auth.SetReadiness(r) }

// SetLeaderResolver installs the resolver that returns the current leader's
// Adapter (the deterministic harness fallback for ready-follower forwarding).
// The live service installs a ForwardClient instead.
func (c *Controller) SetLeaderResolver(fn func() *Adapter) {
	c.leaderResolver = fn
}

// SetForwardClient installs the authenticated Gantry application-RPC forwarding
// transport used by ready-follower mutations. When installed it takes
// precedence over the in-process leader resolver.
func (c *Controller) SetForwardClient(fn ForwardClient) { c.auth.SetForwardClient(fn) }

// State returns the configured mode and runtime readiness.
func (c *Controller) State() (Mode, Readiness) { return c.auth.State() }

// Adapter returns the authoritative mutation authority.
func (c *Controller) Adapter() *Adapter { return c.adapter }

// opID returns a fresh operation identity for a distinct semantic mutation
// intent. The live caller supplies its own request identity (idempotency key);
// absent that plumbing this is the per-intent identity the durable layer keys
// retry deduplication on.
func (c *Controller) opID(prefix string) string {
	if c.adapter == nil {
		return prefix + "-local"
	}
	return c.adapter.opID(prefix)
}

// resolveOpID returns the caller-supplied request identity when present (so the
// same logical HTTP retry maps to the SAME replication operation identity),
// otherwise a fresh per-intent identity.
func (c *Controller) resolveOpID(ctx context.Context, prefix string) string {
	if id := RequestID(ctx); id != "" {
		return id
	}
	return c.opID(prefix)
}

// route applies the authoritative mutation matrix (generic Core Authority):
// standalone -> ErrStandalonePath; ready leader -> propose against the local
// adapter; ready follower -> forward (authenticated ForwardClient with
// read-after-forward wait, or the deterministic in-process leader resolver);
// any other replicated readiness -> reject. It NEVER falls back to local SQL
// for a configured replicated node.
func (c *Controller) route(ctx context.Context, fr ForwardRequest, exec func(*Adapter, context.Context) (*replication.ApplyResult, error)) (*replication.ApplyResult, error) {
	propose := func(ctx context.Context) (*replication.ApplyResult, error) { return exec(c.adapter, ctx) }
	forward := func(ctx context.Context) (*replication.ApplyResult, error) {
		if fc := c.auth.ForwardClient(); fc != nil {
			res, err := fc(ctx, fr)
			if err != nil {
				return nil, err
			}
			if res != nil {
				if err := c.node.WaitApplied(ctx, res.Index); err != nil {
					return nil, err
				}
			}
			return res, nil
		}
		if c.leaderResolver == nil || c.leaderResolver() == nil {
			return nil, errors.New("replicated mutation unavailable: no leader to forward to")
		}
		return exec(c.leaderResolver(), ctx)
	}
	return c.auth.Route(ctx, propose, forward)
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
	fr := ForwardRequest{Kind: KindPostCreate, ObjectID: id, OpID: r.c.resolveOpID(ctx, "post"), Payload: mustJSON(p)}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) {
		return a.CreatePost(ctx, id, p)
	})
}

// UpdatePost routes a post update.
func (r *Router) UpdatePost(ctx context.Context, id string, expectedVersion int64, p PostPayload) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindPostUpdate, ObjectID: id, OpID: r.c.resolveOpID(ctx, "post"), Revision: expectedVersion, Payload: mustJSON(p)}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) {
		return a.UpdatePost(ctx, id, expectedVersion, p)
	})
}

// DeletePost routes a post delete.
func (r *Router) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindPostDelete, ObjectID: id, OpID: r.c.resolveOpID(ctx, "post")}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) { return a.DeletePost(ctx, id) })
}

// AddDependency routes a dependency add.
func (r *Router) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindDependencyAdd, ObjectID: source, OpID: r.c.resolveOpID(ctx, "dep"), Payload: mustJSON(depPayload{DependsOn: depends})}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) {
		return a.AddDependency(ctx, source, depends)
	})
}

// CreateRule routes a rule create.
func (r *Router) CreateRule(ctx context.Context, id string, rl RulePayload) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindRuleCreate, ObjectID: id, OpID: r.c.resolveOpID(ctx, "rule"), Payload: mustJSON(rl)}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) {
		return a.CreateRule(ctx, id, rl)
	})
}

// SetRuleEnabled routes a rule enable/disable.
func (r *Router) SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	fr := ForwardRequest{Kind: KindRuleSetEnable, ObjectID: id, OpID: r.c.resolveOpID(ctx, "rule"), Revision: expectedVersion, Payload: mustJSON(RulePayload{Enabled: enabled})}
	return r.c.route(ctx, fr, func(a *Adapter, ctx context.Context) (*replication.ApplyResult, error) {
		return a.SetRuleEnabled(ctx, id, expectedVersion, enabled)
	})
}

// LeaderProposeHandler is the authenticated leader-side proposal endpoint for
// the Gantry application RPC (generic Core handler mechanics; product routing
// via the leader's own adapter + readiness enforcement).
func (c *Controller) LeaderProposeHandler(authenticate func(r *http.Request) (string, error)) http.Handler {
	return replication.LeaderProposeHandler(authenticate, func(ctx context.Context, fr ForwardRequest) (*replication.ApplyResult, error) {
		if mode, rd := c.State(); mode != ModeReplicated || rd != ReadinessReadyLeader {
			return nil, errors.New("leader not ready")
		}
		return applyForwarded(c.adapter, fr)
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
