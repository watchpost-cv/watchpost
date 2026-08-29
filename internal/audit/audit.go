// Package audit records attributed state changes atomically with the
// mutations they describe. Every privileged mutation inserts its audit row in
// the same database transaction, so an audit-write failure rolls back the
// mutation and the change is never reported as successful.
package audit

import (
	"context"
	"database/sql"
	"time"
)

// Entry describes one attributed state change. ActorID 0 means no
// authenticated user (a machine-authenticated collector or agent, or the
// system itself).
type Entry struct {
	ActorID    int64
	Action     string
	ObjectType string
	ObjectID   string
	Detail     string
}

// Insert writes the audit row inside the caller's transaction.
func Insert(ctx context.Context, tx *sql.Tx, entry Entry) error {
	if len(entry.Detail) > 400 {
		entry.Detail = entry.Detail[:400]
	}
	var actor any
	if entry.ActorID != 0 {
		actor = entry.ActorID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit(at,actor_user_id,action,object_type,object_id,detail) VALUES(?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), actor, entry.Action, entry.ObjectType, entry.ObjectID, entry.Detail)
	return err
}
