package replicated

import (
	"context"
	"database/sql"
)

// cleanupNodeLocal is phase 1 of post.delete apply: a NODE-LOCAL consequence
// required by the Watchpost FK/storage model. It clears the node-local rows
// that FK-reference the post (and its rules), so the replicated semantic
// deletes in phase 2 cannot be FK-blocked. It is deterministic in policy; the
// affected row set is intentionally node-specific (a passive replica's tables
// are empty, so these are no-ops). None of this is replicated state.
func cleanupNodeLocal(ctx context.Context, tx *sql.Tx, postID string) error {
	statements := []string{
		`DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE post_id=?)`,
		`DELETE FROM conversations WHERE post_id=?`,
		`DELETE FROM action_requests WHERE post_id=?`,
		`DELETE FROM device_profile_oids WHERE profile_id IN (SELECT id FROM device_profiles WHERE post_id=?)`,
		`DELETE FROM device_profiles WHERE post_id=?`,
		`DELETE FROM notification_deliveries WHERE alert_id IN (SELECT id FROM alerts WHERE post_id=?)`,
		`DELETE FROM incident_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE post_id=?)`,
		`DELETE FROM alerts WHERE post_id=?`,
		`DELETE FROM observations WHERE post_id=?`,
		`DELETE FROM collector_pairing_tokens WHERE post_id=?`,
		`DELETE FROM collector_keys WHERE post_id=?`,
		`DELETE FROM logs WHERE post_id=?`,
		`DELETE FROM changes WHERE post_id=?`,
	}
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt, postID); err != nil {
			return err
		}
	}
	return nil
}
