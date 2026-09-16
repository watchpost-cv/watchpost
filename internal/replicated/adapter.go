package replicated

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
func (a *Adapter) CreatePost(ctx context.Context, id string, p PostPayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, a.resolveOpID(ctx, "post"), KindPostCreate, id, 0, 0, p)
}

// CreatePostWithOp proposes a post create carrying the forwarded operation
// identity (the follower's request identity, preserved across retries).
func (a *Adapter) CreatePostWithOp(ctx context.Context, id, opID string, p PostPayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, opID, KindPostCreate, id, 0, 0, p)
}

// UpdatePost proposes a post update against an expected object revision.
func (a *Adapter) UpdatePost(ctx context.Context, id string, expectedVersion int64, p PostPayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, a.resolveOpID(ctx, "post"), KindPostUpdate, id, expectedVersion, 0, p)
}

// UpdatePostWithOp proposes a post update carrying the forwarded operation
// identity.
func (a *Adapter) UpdatePostWithOp(ctx context.Context, id, opID string, expectedVersion int64, p PostPayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, opID, KindPostUpdate, id, expectedVersion, 0, p)
}

// DeletePost proposes deletion of a post definition. It is a graph-changing
// operation, so it participates in the same graph-mutation serialization and
// carries the current dependency-graph revision.
func (a *Adapter) DeletePost(ctx context.Context, id string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindPostDelete, a.resolveOpID(ctx, "post"), id, 0, nil, nil)
}

// DeletePostWithOp proposes a post delete carrying the forwarded operation
// identity.
func (a *Adapter) DeletePostWithOp(ctx context.Context, id, opID string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindPostDelete, opID, id, 0, nil, nil)
}

// AddDependency proposes a dependency edge. Semantic validation (endpoints
// exist, !=, no duplicate, no cycle) and the DomainRevision capture happen
// atomically inside the graph-mutation admission lock, so an operation is
// always labelled with the exact graph revision it was validated against.
func (a *Adapter) AddDependency(ctx context.Context, source, depends string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindDependencyAdd, a.resolveOpID(ctx, "dep"), source, 0, depPayload{DependsOn: depends}, func() error {
		return validateDependencyAdd(ctx, a.db, source, depends)
	})
}

// AddDependencyWithOp proposes a dependency edge carrying the forwarded
// operation identity.
func (a *Adapter) AddDependencyWithOp(ctx context.Context, source, opID, depends string) (*replication.ApplyResult, error) {
	return a.graphPropose(ctx, KindDependencyAdd, opID, source, 0, depPayload{DependsOn: depends}, func() error {
		return validateDependencyAdd(ctx, a.db, source, depends)
	})
}

// CreateRule proposes a new rule definition for an existing post.
func (a *Adapter) CreateRule(ctx context.Context, id string, r RulePayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, a.resolveOpID(ctx, "rule"), KindRuleCreate, id, 0, 0, r)
}

// CreateRuleWithOp proposes a rule create carrying the forwarded operation
// identity.
func (a *Adapter) CreateRuleWithOp(ctx context.Context, id, opID string, r RulePayload) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, opID, KindRuleCreate, id, 0, 0, r)
}

// SetRuleEnabled proposes enabling/disabling a rule against an expected
// object revision.
func (a *Adapter) SetRuleEnabled(ctx context.Context, id string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, a.resolveOpID(ctx, "rule"), KindRuleSetEnable, id, expectedVersion, 0, RulePayload{Enabled: enabled})
}

// SetRuleEnabledWithOp proposes a rule enable/disable carrying the forwarded
// operation identity.
func (a *Adapter) SetRuleEnabledWithOp(ctx context.Context, id, opID string, expectedVersion int64, enabled bool) (*replication.ApplyResult, error) {
	return a.proposeOp(ctx, opID, KindRuleSetEnable, id, expectedVersion, 0, RulePayload{Enabled: enabled})
}

// proposeOp builds and proposes a non-graph operation with an explicit
// operation identity (local generation or forwarded request identity).
func (a *Adapter) proposeOp(ctx context.Context, opID, kind, id string, revision, domainRevision int64, payload any) (*replication.ApplyResult, error) {
	if err := a.fsm.ApplyFailure(); err != nil {
		return nil, fmt.Errorf("replica unhealthy: %w", err)
	}
	// Caller-supplied request identity idempotency: an already-applied operation
	// identity with the same semantic intent returns the original committed
	// result (no re-proposal, no second mutation); a changed semantic intent
	// fails closed.
	if prior, ok := a.fsm.AppliedOp(opID); ok && len(prior.Payload) > 0 {
		if !semanticallyEquivalent(kind, prior, id, revision, payload) {
			return nil, fmt.Errorf("operation id %q already applied with a different payload; refusing", opID)
		}
		return prior.Result, nil
	}
	op, err := buildOperation(opID, a.product, kind, id, revision, domainRevision, payload)
	if err != nil {
		return nil, err
	}
	return a.node.Propose(ctx, op)
}

// AppliedIndex returns the locally applied (index, term) of the product FSM.
func (a *Adapter) AppliedIndex() (uint64, uint64) { return a.node.AppliedIndex() }

// resolveOpID returns the caller-supplied request identity when present (the
// durable operation-ID idempotency contract: retries reuse it, identical retries
// dedup, changed payloads fail closed), otherwise a fresh generated identity.
func (a *Adapter) resolveOpID(ctx context.Context, prefix string) string {
	if id := RequestID(ctx); id != "" {
		return id
	}
	return a.opID(prefix)
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
	if err := a.fsm.ApplyFailure(); err != nil {
		return nil, fmt.Errorf("replica unhealthy: %w", err)
	}
	if prior, ok := a.fsm.AppliedOp(opID); ok && len(prior.Payload) > 0 {
		if !semanticallyEquivalent(kind, prior, objectID, revision, payload) {
			return nil, fmt.Errorf("operation id %q already applied with a different payload; refusing", opID)
		}
		return prior.Result, nil
	}
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

// semanticallyEquivalent reports whether a retried mutation carrying the same
// operation identity matches the already-applied operation's SEMANTIC intent
// (the client-visible fields + object precondition), excluding server-generated
// timestamp fields, so a retried HTTP mutation is recognized as identical even
// though the domain regenerates proposal timestamps.
func semanticallyEquivalent(kind string, prior appliedOp, objectID string, revision int64, payload any) bool {
	if prior.Result == nil || prior.Result.ObjectID != objectID || prior.Revision != revision {
		return false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	switch kind {
	case KindPostCreate, KindPostUpdate:
		var p, q PostPayload
		if json.Unmarshal(prior.Payload, &p) != nil || json.Unmarshal(raw, &q) != nil {
			return false
		}
		return p.Name == q.Name && p.Kind == q.Kind && p.Address == q.Address && p.Owner == q.Owner &&
			p.LabelsJSON == q.LabelsJSON && p.Maintenance == q.Maintenance && p.Archived == q.Archived
	case KindRuleCreate:
		var p, q RulePayload
		if json.Unmarshal(prior.Payload, &p) != nil || json.Unmarshal(raw, &q) != nil {
			return false
		}
		return p.PostID == q.PostID && p.Signal == q.Signal && p.Operator == q.Operator && p.Threshold == q.Threshold &&
			p.DurationSeconds == q.DurationSeconds && equalFloatPtr(p.RecoveryThreshold, q.RecoveryThreshold) &&
			p.MissingPolicy == q.MissingPolicy && p.Severity == q.Severity && p.Enabled == q.Enabled
	case KindRuleSetEnable:
		var p, q RulePayload
		if json.Unmarshal(prior.Payload, &p) != nil || json.Unmarshal(raw, &q) != nil {
			return false
		}
		return p.Enabled == q.Enabled
	case KindDependencyAdd:
		var p, q depPayload
		if json.Unmarshal(prior.Payload, &p) != nil || json.Unmarshal(raw, &q) != nil {
			return false
		}
		return p.DependsOn == q.DependsOn
	case KindPostDelete:
		return true // no semantic payload; object identity + revision already compared
	}
	return false
}

func equalFloatPtr(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
