// Package replicated is the CP7D-2 Watchpost replicated-definition adapter.
// It owns the deterministic apply of replicated semantic operations
// (post.create/update/delete, post_dependency.add, rule.create/set_enabled)
// into the Watchpost SQLite tables, plus the dependency-graph revision
// precondition and the two-phase post.delete boundary (node-local cleanup vs
// replicated semantic mutation). It plugs into gantry-core/replication as a
// product StateMachine; standalone mode is unchanged.
package replicated

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

// Operation kinds for the first Watchpost replicated slice.
const (
	KindPostCreate    = "watchpost.post.create"
	KindPostUpdate    = "watchpost.post.update"
	KindPostDelete    = "watchpost.post.delete"
	KindDependencyAdd = "watchpost.post_dependency.add"
	KindRuleCreate    = "watchpost.rule.create"
	KindRuleSetEnable = "watchpost.rule.set_enabled"
)

func validateKind(kind string) error {
	switch kind {
	case KindPostCreate, KindPostUpdate, KindPostDelete, KindDependencyAdd, KindRuleCreate, KindRuleSetEnable:
		return nil
	default:
		return fmt.Errorf("unsupported replicated operation kind %q", kind)
	}
}

// invariantError marks a committed operation that could not be reconciled with
// the expected replicated state. It is a replica-health/invariant violation
// (never an ordinary user-level conflict); deterministic apply fails closed.
type invariantError struct{ msg string }

func (e *invariantError) Error() string { return "replicated apply invariant violation: " + e.msg }

func invariantf(format string, args ...any) error {
	return &invariantError{msg: fmt.Sprintf(format, args...)}
}

// FSM implements replication.StateMachine over the Watchpost SQLite tables
// posts, post_dependencies and rules, materializing committed Operations
// deterministically. Node-local tables are never part of replicated state;
// the only node-local rows it touches are those whose FK constraints make
// deletion of a replicated post/rule impossible, cleaned as an explicit local
// consequence during post.delete apply.
type FSM struct {
	mu           sync.Mutex
	db           *sql.DB
	supported    int
	product      string
	graphRev     int64
	applied      map[string]appliedOp
	appliedIndex uint64
	appliedTerm  uint64
	// persistedIndex is the applied index the SQLite materialization already
	// represents, loaded from replication-adapter metadata on construction.
	// Log entries at or below it are replayed as durable op-ID idempotency only
	// (no mutation, no graph-revision advance), so a durable restart neither
	// double-applies nor destructively clears node-local state.
	persistedIndex uint64
}

type appliedOp struct {
	Digest string                   `json:"digest"`
	Result *replication.ApplyResult `json:"result"`
}

var _ replication.StateMachine = (*FSM)(nil)

// NewFSM returns a product FSM over db, or an error when the replication
// metadata is inconsistent with the materialization (fail closed rather than
// risking duplicate replay or an incorrect graph revision). The posts/
// post_dependencies/rules tables must exist (the Watchpost Store schema). The
// FSM's durable applied position, term and dependency-graph revision are read
// from replication-adapter metadata (_replicated_meta) so the SQLite
// materialization is reconciled with the raft log/snapshot. Ordinary
// construction/restart NEVER clears node-local state: entries at or below the
// persisted applied index are skipped during replay (op-ID idempotency
// recorded, no double mutation).
func NewFSM(db *sql.DB) (*FSM, error) {
	f := &FSM{db: db, supported: replication.Version, applied: make(map[string]appliedOp)}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _replicated_meta(k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		return nil, err
	}
	idxVal, idxPresent, err := metaGet(db, "applied_index")
	if err != nil {
		return nil, err
	}
	if idxPresent {
		f.persistedIndex = idxVal
		f.appliedIndex = idxVal
	} else {
		// No applied position: a genuinely fresh/pre-replication database is
		// empty of replicated materialization. A materialized DB without
		// metadata is corruption and must fail closed, not be treated as fresh.
		n, err := materializationCount(db)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, errors.New("replicated materialization exists without replication metadata; recovery required")
		}
	}
	term, _, err := metaGet(db, "applied_term")
	if err != nil {
		return nil, err
	}
	f.appliedTerm = term
	gr, _, err := metaGet(db, "graph_revision")
	if err != nil {
		return nil, err
	}
	f.graphRev = int64(gr)
	return f, nil
}

// metaGet reads a replication-metadata value. A present but malformed value
// fails closed (returns an error); an absent key is a clean "not present".
func metaGet(db *sql.DB, k string) (uint64, bool, error) {
	var s string
	if err := db.QueryRow(`SELECT v FROM _replicated_meta WHERE k=?`, k).Scan(&s); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var v uint64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, true, fmt.Errorf("corrupt replication metadata %q: %q", k, s)
	}
	return v, true, nil
}

// materializationCount reports whether any replicated definition is present.
func materializationCount(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM posts`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// writeMeta persists the FSM's durable applied position and graph revision
// atomically with the replicated mutation's transaction, so crash safety is
// never separate from the materialization.
func writeMeta(ctx context.Context, tx *sql.Tx, index, term, graphRev uint64) error {
	for _, kv := range []struct {
		key string
		val uint64
	}{{"applied_index", index}, {"applied_term", term}, {"graph_revision", graphRev}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO _replicated_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, kv.key, fmt.Sprintf("%d", kv.val)); err != nil {
			return err
		}
	}
	return nil
}

// GraphRevision returns the replicated dependency-graph revision.
func (f *FSM) GraphRevision() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.graphRev
}

// OpKnown implements replication.StateMachine.
func (f *FSM) OpKnown(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.applied[id]
	if !ok {
		return "", false
	}
	return p.Digest, true
}

// AppliedIndex implements replication.StateMachine.
func (f *FSM) AppliedIndex() (uint64, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appliedIndex, f.appliedTerm
}

// Apply implements raft.FSM.
func (f *FSM) Apply(l *raft.Log) interface{} {
	op, err := replication.DecodeOperation(l.Data)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applyLocked(op, l.Index, l.Term)
}

func (f *FSM) applyLocked(op replication.Operation, index, term uint64) interface{} {
	if op.Version > f.supported {
		return fmt.Errorf("node does not support replication operation version %d (supported: 1..%d)", op.Version, f.supported)
	}
	if err := validateKind(op.Kind); err != nil {
		return err
	}
	digest, err := op.Digest()
	if err != nil {
		return err
	}
	if prior, ok := f.applied[op.ID]; ok {
		if prior.Digest != digest {
			return fmt.Errorf("operation id %q retried with a different payload; refusing", op.ID)
		}
		return prior.Result
	}
	// A durable restart replays the whole raft log from index 0. Entries at or
	// below the persisted applied index are already materialized: record their
	// durable op-ID idempotency from the log and do NOT mutate the DB or
	// advance the graph revision (this is what makes node-local state survive
	// ordinary construction/restart).
	if index <= f.persistedIndex {
		res := &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: op.Revision}
		f.applied[op.ID] = appliedOp{Digest: digest, Result: res}
		f.appliedIndex = index
		f.appliedTerm = term
		return res
	}

	var res *replication.ApplyResult
	switch op.Kind {
	case KindPostCreate:
		res, err = f.applyPostCreate(op, index, term)
	case KindPostUpdate:
		res, err = f.applyPostUpdate(op, index, term)
	case KindPostDelete:
		res, err = f.applyPostDelete(op, index, term)
	case KindDependencyAdd:
		res, err = f.applyDependencyAdd(op, index, term)
	case KindRuleCreate:
		res, err = f.applyRuleCreate(op, index, term)
	case KindRuleSetEnable:
		res, err = f.applyRuleSetEnabled(op, index, term)
	default:
		return fmt.Errorf("unsupported operation kind %q", op.Kind)
	}
	if err != nil {
		return err
	}
	f.applied[op.ID] = appliedOp{Digest: digest, Result: res}
	if f.product == "" {
		f.product = op.Product
	}
	f.appliedIndex = index
	f.appliedTerm = term
	return res
}

// --- operation apply ---------------------------------------------------------

type postPayload struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Address     string `json:"address"`
	Owner       string `json:"owner"`
	LabelsJSON  string `json:"labels_json"`
	Maintenance bool   `json:"maintenance"`
	Archived    bool   `json:"archived"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type depPayload struct {
	DependsOn string `json:"depends_on"`
}

type rulePayload struct {
	PostID            string   `json:"post_id"`
	Signal            string   `json:"signal"`
	Operator          string   `json:"operator"`
	Threshold         float64  `json:"threshold"`
	DurationSeconds   int64    `json:"duration_seconds"`
	RecoveryThreshold *float64 `json:"recovery_threshold,omitempty"`
	MissingPolicy     string   `json:"missing_policy"`
	Severity          string   `json:"severity"`
	Enabled           bool     `json:"enabled"`
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (f *FSM) applyPostCreate(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	var p postPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(context.Background(),
		`INSERT INTO posts(id,name,kind,address,owner,labels_json,maintenance,archived,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?,?)`,
		op.ObjectID, p.Name, p.Kind, p.Address, p.Owner, p.LabelsJSON, boolInt(p.Maintenance), boolInt(p.Archived), p.CreatedAt, p.UpdatedAt); err != nil {
		return nil, invariantf("post.create duplicate or invalid: %v", err)
	}
	if err := writeMeta(ctx, tx, index, term, uint64(f.graphRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: 1}, nil
}

func (f *FSM) applyPostUpdate(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	var p postPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(context.Background(),
		`UPDATE posts SET name=?,address=?,owner=?,labels_json=?,maintenance=?,archived=?,version=version+1,updated_at=? WHERE id=? AND version=?`,
		p.Name, p.Address, p.Owner, p.LabelsJSON, boolInt(p.Maintenance), boolInt(p.Archived), p.UpdatedAt, op.ObjectID, op.Revision)
	if err != nil {
		return nil, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return nil, invariantf("post.update stale revision for %q", op.ObjectID)
	}
	if err := writeMeta(ctx, tx, index, term, uint64(f.graphRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: op.Revision + 1}, nil
}

func (f *FSM) applyPostDelete(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	if op.DomainRevision != f.graphRev {
		return nil, invariantf("post.delete was validated against dependency graph revision %d, current %d", op.DomainRevision, f.graphRev)
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Phase 1 (node-local consequence): clear FK-referencing node-local rows.
	if err := cleanupNodeLocal(ctx, tx, op.ObjectID); err != nil {
		return nil, err
	}
	// Phase 2 (replicated semantic mutation): edges, rules, post.
	if _, err := tx.ExecContext(ctx, `DELETE FROM post_dependencies WHERE post_id=? OR depends_on_id=?`, op.ObjectID, op.ObjectID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rules WHERE post_id=?`, op.ObjectID); err != nil {
		return nil, err
	}
	r, err := tx.ExecContext(ctx, `DELETE FROM posts WHERE id=?`, op.ObjectID)
	if err != nil {
		return nil, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return nil, invariantf("post.delete target %q missing", op.ObjectID)
	}
	newRev := f.graphRev + 1
	if err := writeMeta(ctx, tx, index, term, uint64(newRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	f.graphRev = newRev
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: 0}, nil
}

func (f *FSM) applyDependencyAdd(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	if op.DomainRevision != f.graphRev {
		return nil, invariantf("post_dependency.add was validated against graph revision %d, current %d", op.DomainRevision, f.graphRev)
	}
	if op.ObjectID == "" {
		return nil, invariantf("dependency source is empty")
	}
	var p depPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return nil, err
	}
	if op.ObjectID == p.DependsOn {
		return nil, invariantf("self dependency")
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM posts WHERE id IN (?,?)`, op.ObjectID, p.DependsOn).Scan(&exists); err != nil {
		return nil, err
	}
	if exists != 2 {
		return nil, invariantf("dependency endpoints missing: %q -> %q", op.ObjectID, p.DependsOn)
	}
	var dup int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM post_dependencies WHERE post_id=? AND depends_on_id=?`, op.ObjectID, p.DependsOn).Scan(&dup); err != nil {
		return nil, err
	}
	if dup > 0 {
		return nil, invariantf("duplicate dependency %q -> %q", op.ObjectID, p.DependsOn)
	}
	var cycle int
	if err := tx.QueryRowContext(ctx,
		`WITH RECURSIVE reach(id) AS (SELECT depends_on_id FROM post_dependencies WHERE post_id=? UNION SELECT d.depends_on_id FROM post_dependencies d JOIN reach r ON d.post_id=r.id) SELECT COUNT(*) FROM reach WHERE id=?`,
		p.DependsOn, op.ObjectID).Scan(&cycle); err != nil {
		return nil, err
	}
	if cycle > 0 {
		return nil, invariantf("dependency cycle would be created by %q -> %q", op.ObjectID, p.DependsOn)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO post_dependencies(post_id,depends_on_id) VALUES(?,?)`, op.ObjectID, p.DependsOn); err != nil {
		return nil, invariantf("dependency insert failed: %v", err)
	}
	newRev := f.graphRev + 1
	if err := writeMeta(ctx, tx, index, term, uint64(newRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	f.graphRev = newRev
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: 0}, nil
}

func (f *FSM) applyRuleCreate(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	var p rulePayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO rules(id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version) VALUES(?,?,?,?,?,?,?,?,?,?,1)`,
		op.ObjectID, p.PostID, p.Signal, p.Operator, p.Threshold, p.DurationSeconds, p.RecoveryThreshold, p.MissingPolicy, p.Severity, boolInt(p.Enabled)); err != nil {
		return nil, invariantf("rule.create duplicate or invalid: %v", err)
	}
	if err := writeMeta(ctx, tx, index, term, uint64(f.graphRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: 1}, nil
}

func (f *FSM) applyRuleSetEnabled(op replication.Operation, index, term uint64) (*replication.ApplyResult, error) {
	var p rulePayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE rules SET enabled=?,version=version+1 WHERE id=? AND version=?`, boolInt(p.Enabled), op.ObjectID, op.Revision)
	if err != nil {
		return nil, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return nil, invariantf("rule.set_enabled stale revision for %q", op.ObjectID)
	}
	if err := writeMeta(ctx, tx, index, term, uint64(f.graphRev)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &replication.ApplyResult{Index: index, Term: term, OpID: op.ID, ObjectID: op.ObjectID, Kind: op.Kind, Version: op.Version, Revision: op.Revision + 1}, nil
}

// --- semantic product snapshot ----------------------------------------------

const snapshotFormatVersion = 1

type postRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Address     string `json:"address"`
	Owner       string `json:"owner"`
	Labels      string `json:"labels"`
	Maintenance int    `json:"maintenance"`
	Archived    int    `json:"archived"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type ruleRow struct {
	ID                string   `json:"id"`
	PostID            string   `json:"post_id"`
	Signal            string   `json:"signal"`
	Operator          string   `json:"operator"`
	Threshold         float64  `json:"threshold"`
	DurationSeconds   int64    `json:"duration_seconds"`
	RecoveryThreshold *float64 `json:"recovery_threshold,omitempty"`
	MissingPolicy     string   `json:"missing_policy"`
	Severity          string   `json:"severity"`
	Enabled           int      `json:"enabled"`
	Version           int64    `json:"version"`
}

type snapshotEnvelope struct {
	FormatVersion      int                  `json:"format_version"`
	ReplicationVersion int                  `json:"replication_version"`
	Product            string               `json:"product,omitempty"`
	GraphRevision      int64                `json:"graph_revision"`
	AppliedIndex       uint64               `json:"applied_index"`
	AppliedTerm        uint64               `json:"applied_term"`
	Posts              []postRow            `json:"posts"`
	Dependencies       [][2]string          `json:"dependencies"`
	Rules              []ruleRow            `json:"rules"`
	AppliedOps         map[string]appliedOp `json:"applied_ops"`
	Integrity          string               `json:"integrity"`
}

// Snapshot implements raft.FSM: a canonical, filtered, versioned, integrity-
// protected export of the replicated definitions (posts, post_dependencies,
// rules) plus the dependency-graph revision and durable op-ID idempotency.
// Node-local state never appears.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx := context.Background()
	var posts []postRow
	rows, err := f.db.QueryContext(ctx, `SELECT id,name,kind,address,owner,labels_json,maintenance,archived,version,created_at,updated_at FROM posts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p postRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Address, &p.Owner, &p.Labels, &p.Maintenance, &p.Archived, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		posts = append(posts, p)
	}
	rows.Close()
	var deps [][2]string
	drows, err := f.db.QueryContext(ctx, `SELECT post_id,depends_on_id FROM post_dependencies ORDER BY post_id,depends_on_id`)
	if err != nil {
		return nil, err
	}
	for drows.Next() {
		var a, b string
		if err := drows.Scan(&a, &b); err != nil {
			drows.Close()
			return nil, err
		}
		deps = append(deps, [2]string{a, b})
	}
	drows.Close()
	var rules []ruleRow
	rrows, err := f.db.QueryContext(ctx, `SELECT id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rrows.Next() {
		var r ruleRow
		if err := rrows.Scan(&r.ID, &r.PostID, &r.Signal, &r.Operator, &r.Threshold, &r.DurationSeconds, &r.RecoveryThreshold, &r.MissingPolicy, &r.Severity, &r.Enabled, &r.Version); err != nil {
			rrows.Close()
			return nil, err
		}
		rules = append(rules, r)
	}
	rrows.Close()
	applied := make(map[string]appliedOp, len(f.applied))
	for k, v := range f.applied {
		applied[k] = v
	}
	return &fsmSnapshot{fsm: f, env: snapshotEnvelope{
		FormatVersion: snapshotFormatVersion, ReplicationVersion: f.supported, Product: f.product,
		GraphRevision: f.graphRev, AppliedIndex: f.appliedIndex, AppliedTerm: f.appliedTerm,
		Posts: posts, Dependencies: deps, Rules: rules, AppliedOps: applied,
	}}, nil
}

// Restore implements raft.FSM: atomically replace the replicated definitions
// and graph revision from a verified snapshot. Node-local rows referencing the
// replaced replicated parents are cleared as a local consequence (on a fresh
// learner they are absent).
func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	var env snapshotEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	if env.FormatVersion != snapshotFormatVersion {
		return fmt.Errorf("unsupported snapshot format version %d", env.FormatVersion)
	}
	if env.ReplicationVersion > replication.Version {
		return fmt.Errorf("unsupported snapshot replication version %d", env.ReplicationVersion)
	}
	// Integrity verification before any mutation.
	cp := env
	cp.Integrity = ""
	raw, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if env.Integrity != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("snapshot integrity mismatch")
	}

	ctx := context.Background()
	f.mu.Lock()
	defer f.mu.Unlock()
	// Snapshot-position-aware reconciliation. A verified snapshot presented
	// during ordinary restart recovery may be at or behind the local SQLite
	// materialization (raft restores its persisted snapshot before replaying
	// the trailing log). In that case the local materialization is already at
	// least as current as the snapshot: do NOT roll product SQLite backward or
	// erase node-local history. Seed durable op-ID knowledge from the snapshot
	// for entries the retained log no longer replays (raft replays only entries
	// after the snapshot index), and leave applied position/graph revision at
	// the materialized P.
	if env.AppliedIndex <= f.persistedIndex {
		for k, v := range env.AppliedOps {
			if _, ok := f.applied[k]; !ok {
				f.applied[k] = v
			}
		}
		return nil
	}
	// Forward snapshot replacement (genuine catch-up to a newer authoritative
	// snapshot): validated semantic replacement; the frozen snapshot-replacement
	// policy clears FK-referencing node-local children as a local consequence.
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Clear prior replicated definitions; clear referencing node-local rows as
	// a local consequence so the FK web cannot block replacement.
	if err := clearReplicated(tx, ctx); err != nil {
		return err
	}
	for _, p := range env.Posts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO posts(id,name,kind,address,owner,labels_json,maintenance,archived,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			p.ID, p.Name, p.Kind, p.Address, p.Owner, p.Labels, p.Maintenance, p.Archived, p.Version, p.CreatedAt, p.UpdatedAt); err != nil {
			return err
		}
	}
	for _, d := range env.Dependencies {
		if _, err := tx.ExecContext(ctx, `INSERT INTO post_dependencies(post_id,depends_on_id) VALUES(?,?)`, d[0], d[1]); err != nil {
			return err
		}
	}
	for _, r := range env.Rules {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rules(id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.PostID, r.Signal, r.Operator, r.Threshold, r.DurationSeconds, r.RecoveryThreshold, r.MissingPolicy, r.Severity, r.Enabled, r.Version); err != nil {
			return err
		}
	}
	if err := writeMeta(ctx, tx, env.AppliedIndex, env.AppliedTerm, uint64(env.GraphRevision)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	f.product = env.Product
	f.graphRev = env.GraphRevision
	f.appliedIndex = env.AppliedIndex
	f.persistedIndex = env.AppliedIndex
	f.appliedTerm = env.AppliedTerm
	f.applied = env.AppliedOps
	if f.applied == nil {
		f.applied = make(map[string]appliedOp)
	}
	return nil
}

// clearReplicated clears replicated definitions and their FK-referencing
// node-local rows (local consequence) so a snapshot can be installed cleanly.
func clearReplicated(tx *sql.Tx, ctx context.Context) error {
	// Node-local FK children first (alerts reference rules/posts, etc.).
	for _, stmt := range []string{
		`DELETE FROM notification_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE post_id IN (SELECT id FROM posts))`,
		`DELETE FROM incident_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE post_id IN (SELECT id FROM posts))`,
		`DELETE FROM alerts WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM observations WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE post_id IN (SELECT id FROM posts))`,
		`DELETE FROM conversations WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM action_requests WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM device_profile_oids WHERE profile_id IN (SELECT id FROM device_profiles WHERE post_id IN (SELECT id FROM posts))`,
		`DELETE FROM device_profiles WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM collector_pairing_tokens WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM collector_keys WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM logs WHERE post_id IN (SELECT id FROM posts)`,
		`DELETE FROM changes WHERE post_id IN (SELECT id FROM posts)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, stmt := range []string{
		`DELETE FROM post_dependencies WHERE post_id IN (SELECT id FROM posts) OR depends_on_id IN (SELECT id FROM posts)`,
		`DELETE FROM rules`,
		`DELETE FROM posts`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

type fsmSnapshot struct {
	fsm *FSM
	env snapshotEnvelope
}

var _ raft.FSMSnapshot = (*fsmSnapshot)(nil)

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	cp := s.env
	cp.Integrity = ""
	raw, err := json.Marshal(cp)
	if err != nil {
		_ = sink.Cancel()
		return err
	}
	sum := sha256.Sum256(raw)
	s.env.Integrity = hex.EncodeToString(sum[:])
	b, err := json.Marshal(s.env)
	if err != nil {
		_ = sink.Cancel()
		return err
	}
	if _, err := sink.Write(b); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}
