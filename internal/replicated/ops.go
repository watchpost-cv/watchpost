package replicated

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/gantry-tools/gantry-core/replication"
)

// buildOperation constructs a canonical semantic Operation for the Watchpost
// dependency domain. DomainRevision is the replicated dependency-graph
// revision the operation was validated against (0 for non-graph ops).
func buildOperation(id, product, kind, objectID string, revision int64, domainRev int64, payload any) (replication.Operation, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		return replication.Operation{}, err
	}
	return replication.Operation{
		ID: id, Product: product, Version: replication.Version, Kind: kind,
		ObjectKind: "post", ObjectID: objectID, Revision: revision, DomainRevision: domainRev,
		Payload: p, OriginNode: product,
	}, nil
}

// cycleCTE detects whether adding source -> depends would create a cycle over
// the existing replicated post_dependencies graph.
const cycleCTE = `WITH RECURSIVE reach(id) AS (
	SELECT depends_on_id FROM post_dependencies WHERE post_id=?
	UNION SELECT d.depends_on_id FROM post_dependencies d JOIN reach r ON d.post_id=r.id
) SELECT COUNT(*) FROM reach WHERE id=?`

// validateDependencyAdd performs the static pre-proposal validations for a
// post_dependency.add edge against the authoritative applied replicated graph
// (the product DB on the leader). The leader-side graph-revision check is
// applied by the adapter around this. Returns nil when the edge is valid.
func validateDependencyAdd(ctx context.Context, db *sql.DB, source, depends string) error {
	if source == "" || depends == "" {
		return fmt.Errorf("dependency endpoints must be non-empty")
	}
	if source == depends {
		return fmt.Errorf("self dependency")
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM posts WHERE id IN (?,?)`, source, depends).Scan(&exists); err != nil {
		return err
	}
	if exists != 2 {
		return fmt.Errorf("dependency endpoints %q -> %q must exist as replicated posts", source, depends)
	}
	var dup int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM post_dependencies WHERE post_id=? AND depends_on_id=?`, source, depends).Scan(&dup); err != nil {
		return err
	}
	if dup > 0 {
		return fmt.Errorf("duplicate dependency %q -> %q", source, depends)
	}
	var cycle int
	if err := db.QueryRowContext(ctx, cycleCTE, depends, source).Scan(&cycle); err != nil {
		return err
	}
	if cycle > 0 {
		return fmt.Errorf("dependency cycle would be created by %q -> %q", source, depends)
	}
	return nil
}
