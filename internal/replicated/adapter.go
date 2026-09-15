package replicated

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"sync"

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

	// graphMu serializes graph-mutation admission (validate -> DomainRevision
	// capture -> propose -> applied) within the leader process, so a graph
	// operation is never validated against one graph revision and labelled
	// with another. It is process-local coordination; DomainRevision remains
	// the durable semantic contract across leadership change/retry/replay.
	graphMu sync.Mutex

	// BeforeGraphValidate is a deterministic test hook fired inside the
	// admission lock just before a graph operation is validated/admitted.
	BeforeGraphValidate func()
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
// operation, so it participates in the same graph-mutation serialization and
// carries the current dependency-graph revision.
func (a *Adapter) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindPostDelete, a.opID("post"), id, 0, nil, nil)
}

// AddDependency proposes a dependency edge. Semantic validation (endpoints
// exist, !=, no duplicate, no cycle) and the DomainRevision capture happen
// atomically inside the graph-mutation admission lock, so an operation is
// always labelled with the exact graph revision it was validated against.
func (a *Adapter) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindDependencyAdd, a.opID("dep"), source, 0, depPayload{DependsOn: depends}, func() error {
		return validateDependencyAdd(ctx, a.db, source, depends)
	})
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

// graphPropose is the serialized admission boundary for graph-changing
// operations: acquire the graph lock, capture the current revision G, run any
// semantic validation against G, verify the graph is still G, build the
// operation with DomainRevision=G, propose, and await commit + apply before
// releasing the lock. This makes validation -> DomainRevision binding atomic:
// an operation can never be labelled with a revision it was not validated
// against.
func (a *Adapter) graphPropose(ctx context.Context, kind, opID, objectID string, revision int64, payload any, validate func() error) (*replication.ApplyResult, error) {
	a.graphMu.Lock()
	defer a.graphMu.Unlock()
	if a.BeforeGraphValidate != nil {
		a.BeforeGraphValidate()
	}
	g := a.fsm.GraphRevision()
	if validate != nil {
		if err := validate(); err != nil {
			return nil, err
		}
	}
	if a.fsm.GraphRevision() != g {
		return nil, fmt.Errorf("dependency graph changed during validation (revision %d -> %d); revalidate the intent", g, a.fsm.GraphRevision())
	}
	op, err := buildOperation(opID, a.product, kind, objectID, revision, g, payload)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}
