package collectorhealth

import (
	"context"
	"database/sql"
	"time"

	"github.com/watchpost-cv/watchpost/internal/store"
)

type Health struct {
	CollectorID    string     `json:"collector_id"`
	PostID         string     `json:"post_id"`
	Status         string     `json:"status"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	LastObservedAt *time.Time `json:"last_observed_at"`
	LastError      string     `json:"last_error"`
	RejectedCount  int64      `json:"rejected_count"`
}
type Store struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Store { return &Store{s: s, now: time.Now} }

func (s *Store) List(ctx context.Context) ([]Health, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,post_id,last_seen_at,last_observed_at,last_sent_at,last_error,last_rejected_at,rejected_count,partial,revoked_at FROM collector_keys WHERE kind='collector' ORDER BY post_id,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Health{}
	now := s.now().UTC()
	for rows.Next() {
		var item Health
		var seen, observed, sent, rejected, revoked sql.NullString
		var partial bool
		if err = rows.Scan(&item.CollectorID, &item.PostID, &seen, &observed, &sent, &item.LastError, &rejected, &item.RejectedCount, &partial, &revoked); err != nil {
			return nil, err
		}
		item.LastSeenAt = parseTime(seen)
		item.LastObservedAt = parseTime(observed)
		item.Status = status(now, seen, sent, rejected, revoked, partial)
		result = append(result, item)
	}
	return result, rows.Err()
}

func status(now time.Time, seen, sent, rejected, revoked sql.NullString, partial bool) string {
	if revoked.Valid {
		return "revoked"
	}
	if rejected.Valid && (!seen.Valid || rejected.String > seen.String) {
		return "rejected"
	}
	if !seen.Valid {
		return "never_connected"
	}
	seenAt, _ := time.Parse(time.RFC3339Nano, seen.String)
	if now.Sub(seenAt) > 10*time.Minute {
		return "offline"
	}
	if now.Sub(seenAt) > 2*time.Minute {
		return "stale"
	}
	if sent.Valid {
		sentAt, _ := time.Parse(time.RFC3339Nano, sent.String)
		difference := now.Sub(sentAt)
		if difference > 5*time.Minute || difference < -5*time.Minute {
			return "skewed"
		}
	}
	if partial {
		return "partial"
	}
	return "healthy"
}
func parseTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &parsed
}
