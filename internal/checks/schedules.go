package checks

import (
	"context"
	"errors"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

type Schedule struct {
	ID, PostID, Kind, Address, ServerName string
	IntervalSeconds                       int64
	Enabled                               bool
	NextRunAt                             time.Time
	Last                                  *StoredResult
}
type StoredResult struct {
	CheckedAt time.Time  `json:"checked_at"`
	OK        bool       `json:"ok"`
	LatencyMS float64    `json:"latency_ms"`
	Status    int        `json:"status,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Failure   string     `json:"failure,omitempty"`
}
type ScheduleStore struct{ s *store.Store }

func NewScheduleStore(s *store.Store) *ScheduleStore { return &ScheduleStore{s: s} }
func (s *ScheduleStore) Save(ctx context.Context, v Schedule) error {
	if v.ID == "" || v.PostID == "" || v.Address == "" || v.IntervalSeconds < 30 || v.IntervalSeconds > 86400 {
		return errors.New("invalid check schedule")
	}
	if !map[string]bool{"http": true, "tcp": true, "tls": true, "dns": true, "icmp": true}[v.Kind] {
		return errors.New("unsupported check kind")
	}
	now := time.Now().UTC()
	_, err := s.s.DB.ExecContext(ctx, `INSERT INTO check_schedules(id,post_id,kind,address,server_name,interval_seconds,enabled,next_run_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.PostID, v.Kind, v.Address, v.ServerName, v.IntervalSeconds, true, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}
func (s *ScheduleStore) List(ctx context.Context) ([]Schedule, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT c.id,c.post_id,c.kind,c.address,c.server_name,c.interval_seconds,c.enabled,c.next_run_at,r.checked_at,r.ok,r.latency_ms,r.status,r.expires_at,r.failure FROM check_schedules c LEFT JOIN check_results r ON r.id=(SELECT id FROM check_results WHERE schedule_id=c.id ORDER BY checked_at DESC LIMIT 1) ORDER BY c.post_id,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Schedule{}
	for rows.Next() {
		var v Schedule
		var next string
		var checked, expires, failure *string
		var ok *bool
		var latency *float64
		var status *int
		if err = rows.Scan(&v.ID, &v.PostID, &v.Kind, &v.Address, &v.ServerName, &v.IntervalSeconds, &v.Enabled, &next, &checked, &ok, &latency, &status, &expires, &failure); err != nil {
			return nil, err
		}
		v.NextRunAt, _ = time.Parse(time.RFC3339Nano, next)
		if checked != nil {
			at, _ := time.Parse(time.RFC3339Nano, *checked)
			v.Last = &StoredResult{CheckedAt: at, OK: *ok, LatencyMS: *latency, Status: *status, Failure: *failure}
			if expires != nil {
				x, _ := time.Parse(time.RFC3339Nano, *expires)
				v.Last.ExpiresAt = &x
			}
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func (s *ScheduleStore) RunDue(ctx context.Context, runner *Runner, now time.Time) (int, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,kind,address,server_name,interval_seconds FROM check_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT 32`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	type due struct {
		id, kind, address, server string
		interval                  int64
	}
	var work []due
	for rows.Next() {
		var v due
		if err = rows.Scan(&v.id, &v.kind, &v.address, &v.server, &v.interval); err != nil {
			rows.Close()
			return 0, err
		}
		work = append(work, v)
	}
	rows.Close()
	for _, v := range work {
		result := runner.Run(ctx, v.kind, v.address, v.server)
		var expires any
		if result.ExpiresAt != nil {
			expires = result.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		tx, e := s.s.DB.BeginTx(ctx, nil)
		if e != nil {
			return 0, e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO check_results(schedule_id,checked_at,ok,latency_ms,status,expires_at,failure) VALUES(?,?,?,?,?,?,?)`, v.id, now.UTC().Format(time.RFC3339Nano), result.OK, float64(result.Latency)/float64(time.Millisecond), result.Status, expires, result.Failure)
		if e == nil {
			_, e = tx.ExecContext(ctx, `UPDATE check_schedules SET next_run_at=? WHERE id=?`, now.UTC().Add(time.Duration(v.interval)*time.Second).Format(time.RFC3339Nano), v.id)
		}
		if e != nil {
			tx.Rollback()
			return 0, e
		}
		if e = tx.Commit(); e != nil {
			return 0, e
		}
	}
	return len(work), nil
}
