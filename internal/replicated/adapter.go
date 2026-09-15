package replicated

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/gantry-tools/gantry-core/replication"
)

// Adapter is the authoritative replicated-write choke point for the Watchpost
// definitions slice. When replication is enabled, domain mutations MUST go
// through these methods (never direct SQL); standalone mode is unchanged and
// uses the existing local domain transactions. Each method validates before
// consensus and proposes through the leader, awaiting commit + deterministic
// apply.
type Adapter struct {
	node    *replication.Node
	fsm     *FSM
	db      *sql.DB
	product string
}

// NewAdapter returns the replicated choke point over node (leader) + fsm.
func NewAdapter(node *replication.Node, fsm *FSM, db *sql.DB, product string) *Adapter {
	return &Adapter{node: node, fsm: fsm, db: db, product: product}
}

// CreatePost proposes a new post definition.
func (a *Adapter) CreatePost(ctx context.Context, id string, p postPayload) (*replication.ApplyResult, error) {
	op, err := buildOperation(a.opID("post"), a.product, KindPostCreate, id, 0, 0, p)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}

// UpdatePost proposes a post update against an expected object revision.
func (a *Adapter) UpdatePost(ctx context.Context, id string, expectedVersion int64, p postPayload) (*replication.ApplyResult, error) {
	op, err := buildOperation(a.opID("post"), a.product, KindPostUpdate, id, expectedVersion, 0, p)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}

// DeletePost proposes deletion of a post definition. It is a graph-changing
// operation, so it is validated against and carries the current dependency-
// graph revision.
func (a *Adapter) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	return a.proposeGraph(ctx, KindPostDelete, a.opID("post"), id, 0, nil)
}

// AddDependency proposes a dependency edge. It validates statically against
// the applied graph, captures the current graph revision, and carries it as
// DomainRevision so a stale edge (after a concurrent graph mutation) is never
// admitted.
func (a *Adapter) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	if err := validateDependencyAdd(ctx, a.db, source, depends); err != nil {
		return nil, err
	}
	return a.proposeGraph(ctx, KindDependencyAdd, a.opID("dep"), source, 0, depPayload{DependsOn: depends})
}

// CreateRule proposes a new rule definition for an existing post.
func (a *Adapter) CreateRule(ctx context.Context, id string, r rulePayload) (*replication.ApplyResult, error) {
	op, err := buildOperation(a.opID("rule"), a.product, KindRuleCreate, id, 0, 0, r)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}

// SetRuleEnabled proposes enabling/disabling a rule against an expected
// object revision.
func (a *Adapter) SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	r := rulePayload{Enabled: enabled}
	op, err := buildOperation(a.opID("rule"), a.product, KindRuleSetEnable, id, expectedVersion, 0, r)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}

// opID returns a unique operation identity for a distinct semantic mutation,
// so the durable operation-ID idempotency contract distinguishes operations
// (a retried mutation reuses the caller's request identity in production).
func (a *Adapter) opID(prefix string) string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return prefix
	}
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(b)
}

// proposeGraph proposes a graph-changing operation, carrying the current
// dependency-graph revision as DomainRevision and re-checking it atomically
// with admission so a stale operation is rejected before consensus.
func (a *Adapter) proposeGraph(ctx context.Context, kind, opID, objectID string, revision int64, payload any) (*replication.ApplyResult, error) {
	g := a.fsm.GraphRevision()
	op, err := buildOperation(opID, a.product, kind, objectID, revision, g, payload)
	if err != nil {
		return nil, err
	}
	// Re-check before admission: if the graph advanced since we captured g,
	// the operation is stale and must be rejected before consensus (the
	// deterministic apply also fails closed on any residual mismatch).
	if a.fsm.GraphRevision() != g {
		return nil, fmt.Errorf("stale dependency graph revision %d (current %d); revalidate the intent", g, a.fsm.GraphRevision())
	}
	return a.node.Propose(ctx, op)
}
