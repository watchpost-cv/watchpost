package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/history"
	"github.com/watchpost-cv/watchpost/internal/store"
)

// maxPasses bounds the rows removed per category in one pass so a backlogged
// table cannot monopolise the single database connection or grow the WAL
// without limit. Work resumes on the next pass.
const maxPasses = 250

const layout = time.RFC3339Nano

type Store struct {
	s      *store.Store
	policy config.Retention
	now    func() time.Time
	batch  int
}

type Report struct {
	Categories map[string]int64
	Truncated  []string
	Duration   time.Duration
}

func (r Report) Total() int64 {
	var total int64
	for _, count := range r.Categories {
		total += count
	}
	return total
}

func New(s *store.Store, policy config.Retention) *Store {
	batch := policy.Batch
	if batch < 1 {
		batch = 1000
	}
	return &Store{s: s, policy: policy, now: time.Now, batch: batch}
}

// NewAt builds a retention store with an explicit clock for deterministic
// virtual-clock tests.
func NewAt(s *store.Store, policy config.Retention, now func() time.Time) *Store {
	store := New(s, policy)
	store.now = now
	return store
}

func (r *Store) Policy() config.Retention { return r.policy }

// RunOnce performs one deterministic pruning pass. A category with a zero
// policy window keeps everything forever, except sessions which are always
// pruned as soon as they expire.
func (r *Store) RunOnce(ctx context.Context) (Report, error) {
	started := time.Now()
	report := Report{Categories: map[string]int64{}}
	now := r.now().UTC()

	categories := []struct {
		name   string
		when   time.Duration
		always bool
		prune  func(cutoff string) (int64, bool, error)
	}{
		{"sessions", 0, true, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE expires_at<? ORDER BY token_hash LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"bootstrap_tokens", 0, true, func(cutoff string) (int64, bool, error) {
			// Expired or already-consumed bootstrap tokens are inert after
			// first-admin setup completes; an unexpired pending token stays.
			removed, err := r.deleteBounded(ctx, "DELETE FROM bootstrap_tokens WHERE token_hash IN (SELECT token_hash FROM bootstrap_tokens WHERE COALESCE(consumed_at,expires_at)<? ORDER BY token_hash LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"observations", r.policy.Observations, false, func(cutoff string) (int64, bool, error) {
			return r.bounded(ctx, cutoff, func(ctx context.Context, cutoff string) (int64, error) {
				cutoffTime, err := time.Parse(layout, cutoff)
				if err != nil {
					return 0, err
				}
				return history.New(r.s).Retain(ctx, cutoffTime, r.batch)
			})
		}},
		{"check_results", r.policy.CheckResults, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM check_results WHERE id IN (SELECT id FROM check_results WHERE checked_at<? ORDER BY id LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"logs", r.policy.Logs, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, `DELETE FROM logs WHERE id IN (SELECT id FROM logs WHERE observed_at<? AND NOT EXISTS (SELECT 1 FROM conversation_evidence ce WHERE ce.kind='log' AND ce.evidence_id=logs.id) ORDER BY id LIMIT ?)`, cutoff)
			return removed, false, err
		}},
		{"changes", r.policy.Changes, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, `DELETE FROM changes WHERE id IN (SELECT id FROM changes WHERE occurred_at<? AND NOT EXISTS (SELECT 1 FROM conversation_evidence ce WHERE ce.kind='change' AND ce.evidence_id=changes.id) ORDER BY id LIMIT ?)`, cutoff)
			return removed, false, err
		}},
		{"alerts", r.policy.AlertsResolved, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, `DELETE FROM alerts WHERE id IN (
				SELECT a.id FROM alerts a
				WHERE
					((a.state IN ('pending','firing','acknowledged','suppressed') AND a.updated_at<? AND a.id NOT IN (SELECT MAX(n.id) FROM alerts n GROUP BY n.rule_id,n.post_id))
					 OR (a.state='resolved' AND a.resolved_at IS NOT NULL AND a.resolved_at<?))
					AND NOT EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id=a.id)
					AND NOT EXISTS (SELECT 1 FROM conversation_evidence ce WHERE ce.kind='alert' AND ce.evidence_id=a.id)
				ORDER BY a.id LIMIT ?)`, cutoff, cutoff)
			return removed, false, err
		}},
		{"notification_deliveries", r.policy.Deliveries, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM notification_deliveries WHERE id IN (SELECT id FROM notification_deliveries WHERE state='delivered' AND delivered_at<? ORDER BY id LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"pairing_tokens", r.policy.PairingTokens, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM collector_pairing_tokens WHERE token_hash IN (SELECT token_hash FROM collector_pairing_tokens WHERE COALESCE(used_at,expires_at)<? ORDER BY token_hash LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"pairing_requests", r.policy.PairingRequests, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM agent_pairing_requests WHERE id IN (SELECT id FROM agent_pairing_requests WHERE COALESCE(terminal_at,expires_at)<? ORDER BY id LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"federation_inbox", r.policy.FederationInbox, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM federation_inbox WHERE rowid IN (SELECT rowid FROM federation_inbox WHERE received_at<? ORDER BY rowid LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"federation_outbox", r.policy.FederationOutbox, false, func(cutoff string) (int64, bool, error) {
			removed, err := r.deleteBounded(ctx, "DELETE FROM federation_outbox WHERE id IN (SELECT id FROM federation_outbox WHERE delivered_at IS NOT NULL AND delivered_at<? ORDER BY id LIMIT ?)", cutoff)
			return removed, false, err
		}},
		{"conversations", r.policy.Conversations, false, func(cutoff string) (int64, bool, error) {
			// Orphaned conversations (no post, no incident) and their messages
			// and evidence references cascade.
			removed, err := r.deleteBounded(ctx, "DELETE FROM conversations WHERE id IN (SELECT id FROM conversations WHERE post_id IS NULL AND incident_id IS NULL AND created_at<? ORDER BY id LIMIT ?)", cutoff)
			return removed, false, err
		}},
	}
	for _, category := range categories {
		if category.when < 0 || (category.when == 0 && !category.always) {
			continue
		}
		cutoff := now.Add(-category.when).Format(layout)
		removed, truncated, err := category.prune(cutoff)
		if err != nil {
			return report, fmt.Errorf("prune %s: %w", category.name, err)
		}
		report.Categories[category.name] = removed
		if truncated {
			report.Truncated = append(report.Truncated, category.name)
		}
	}
	if len(report.Truncated) > 0 || report.Total() > 0 {
		r.checkpoint(ctx)
	}
	report.Duration = time.Since(started)
	return report, nil
}

// bounded runs a per-batch prune until fewer than batch rows remain or the
// per-pass cap is reached.
func (r *Store) bounded(ctx context.Context, cutoff string, prune func(context.Context, string) (int64, error)) (int64, bool, error) {
	var total int64
	for pass := 0; pass < maxPasses; pass++ {
		removed, err := prune(ctx, cutoff)
		if err != nil {
			return total, false, err
		}
		total += removed
		if removed < int64(r.batch) {
			return total, false, nil
		}
	}
	return total, true, nil
}

func (r *Store) deleteBounded(ctx context.Context, statement string, args ...any) (int64, error) {
	all := append([]any{}, args...)
	all = append(all, r.batch)
	result, err := r.s.DB.ExecContext(ctx, statement, all...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// checkpoint opportunistically reclaims WAL space after pruning. A checkpoint
// fails harmlessly when a concurrent reader holds the database open.
func (r *Store) checkpoint(ctx context.Context) {
	_, _ = r.s.DB.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
}

func (r *Store) RunLoop(ctx context.Context) {
	if r.policy.Interval <= 0 {
		return
	}
	ticker := time.NewTicker(r.policy.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = r.RunOnce(ctx)
		}
	}
}
