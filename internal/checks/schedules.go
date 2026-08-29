package checks

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/contract"
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

// DueResult is one executed scheduled check plus its stored result, returned
// so the server can route it into the canonical observation and rule pipeline.
type DueResult struct {
	Schedule Schedule
	Result   Result
}

type ScheduleStore struct {
	s      *store.Store
	policy *Policy
}

func NewScheduleStore(s *store.Store) *ScheduleStore { return &ScheduleStore{s: s} }

// NewScheduleStoreWithPolicy applies target allow/deny rules at schedule
// creation and again at run time (defending against DNS rebinding).
func NewScheduleStoreWithPolicy(s *store.Store, policy *Policy) *ScheduleStore {
	return &ScheduleStore{s: s, policy: policy}
}
func (s *ScheduleStore) Save(ctx context.Context, v Schedule, entry audit.Entry) error {
	if v.ID == "" || v.PostID == "" || v.Address == "" || v.IntervalSeconds < 30 || v.IntervalSeconds > 86400 {
		return errors.New("invalid check schedule")
	}
	if !map[string]bool{"http": true, "tcp": true, "tls": true, "dns": true, "icmp": true}[v.Kind] {
		return errors.New("unsupported check kind")
	}
	if s.policy != nil {
		if err := s.policy.Validate(ctx, v.Address, 0); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO check_schedules(id,post_id,kind,address,server_name,interval_seconds,enabled,next_run_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.PostID, v.Kind, v.Address, v.ServerName, v.IntervalSeconds, true, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// A central check owns a post-scoped source identity so its observations
	// satisfy the observation FK and carry a canonical Source. The secret hash
	// is a fixed marker: it is never a bearer credential and never exposed.
	marker := sha256.Sum256([]byte("central-check:" + v.ID))
	if _, err = tx.ExecContext(ctx, `INSERT INTO collector_keys(id,post_id,secret_hash,kind) VALUES(?,?,?,'central_check') ON CONFLICT(id) DO NOTHING`, v.ID, v.PostID, marker[:]); err != nil {
		return err
	}
	entry.ObjectType = "check_schedule"
	entry.ObjectID = v.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

// Get fetches a single schedule by id.
func (s *ScheduleStore) Get(ctx context.Context, id string) (Schedule, error) {
	var v Schedule
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,post_id,kind,address,server_name,interval_seconds,enabled FROM check_schedules WHERE id=?`, id).Scan(&v.ID, &v.PostID, &v.Kind, &v.Address, &v.ServerName, &v.IntervalSeconds, &v.Enabled)
	if err != nil {
		return Schedule{}, err
	}
	return v, nil
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

type due struct {
	id, post, kind, address, server string
	interval                        int64
}

// RunDue executes due schedules in bounded batches and returns the results so
// callers can route them through the canonical observation and rule pipeline.
// Network probes run on a bounded worker pool; result storage is sequential so
// the single database connection is never contended by parallel writes.
func (s *ScheduleStore) RunDue(ctx context.Context, runner *Runner, now time.Time, workers int) ([]DueResult, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,post_id,kind,address,server_name,interval_seconds FROM check_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT 32`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	var work []due
	for rows.Next() {
		var v due
		if err = rows.Scan(&v.id, &v.post, &v.kind, &v.address, &v.server, &v.interval); err != nil {
			rows.Close()
			return nil, err
		}
		work = append(work, v)
	}
	rows.Close()
	if workers < 1 {
		workers = 1
	}
	results := make([]DueResult, len(work))
	semaphore := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for index, v := range work {
		wg.Add(1)
		go func(index int, v due) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			results[index] = DueResult{Schedule: Schedule{ID: v.id, PostID: v.post, Kind: v.kind, Address: v.address, ServerName: v.server, IntervalSeconds: v.interval}, Result: s.runWithPolicy(ctx, runner, v)}
		}(index, v)
	}
	wg.Wait()
	for index, v := range work {
		result := results[index].Result
		var expires any
		if result.ExpiresAt != nil {
			expires = result.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		tx, e := s.s.DB.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO check_results(schedule_id,checked_at,ok,latency_ms,status,expires_at,failure) VALUES(?,?,?,?,?,?,?)`, v.id, now.UTC().Format(time.RFC3339Nano), result.OK, float64(result.Latency)/float64(time.Millisecond), result.Status, expires, result.Failure)
		if e == nil {
			_, e = tx.ExecContext(ctx, `UPDATE check_schedules SET next_run_at=? WHERE id=?`, now.UTC().Add(time.Duration(v.interval)*time.Second).Format(time.RFC3339Nano), v.id)
		}
		if e != nil {
			tx.Rollback()
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	return results, nil
}

// runWithPolicy re-applies target policy at run time so a hostname that
// resolves differently than it did at creation (DNS rebinding) is refused
// rather than probed.
func (s *ScheduleStore) runWithPolicy(ctx context.Context, runner *Runner, v due) Result {
	if s.policy != nil {
		if err := s.policy.Validate(ctx, v.address, 0); err != nil {
			return Result{Kind: v.kind, Address: v.address, Failure: err.Error()}
		}
	}
	return runner.Run(ctx, v.kind, v.address, v.server)
}

// Observations converts a stored check result into the canonical observation
// envelope. A failed check is a known fact: the `<kind>.ok` observation is 0
// with good quality so a deterministic rule can fire. Latency is measured in
// all cases; a TLS certificate expiry horizon is emitted when present.
func (r Result) Observations(method contract.Method, observedAt time.Time) []contract.Observation {
	ok := 0.0
	if r.OK {
		ok = 1.0
	}
	source := contract.Source{Method: method, Identity: method.ID}
	result := []contract.Observation{{
		Version: contract.ProtocolVersion, PostID: method.PostID, Source: source,
		Signal: r.Kind + ".ok", Value: &ok, Unit: "boolean", Quality: contract.QualityGood,
		ObservedAt: observedAt, IngestedAt: observedAt, FreshUntil: observedAt.Add(time.Hour),
	}}
	latency := float64(r.Latency) / float64(time.Millisecond)
	result = append(result, contract.Observation{
		Version: contract.ProtocolVersion, PostID: method.PostID, Source: source,
		Signal: r.Kind + ".latency_ms", Value: &latency, Unit: "ms", Quality: contract.QualityGood,
		ObservedAt: observedAt, IngestedAt: observedAt, FreshUntil: observedAt.Add(time.Hour),
	})
	if r.Kind == "tls" && r.ExpiresAt != nil {
		days := r.ExpiresAt.Sub(observedAt).Hours() / 24
		result = append(result, contract.Observation{
			Version: contract.ProtocolVersion, PostID: method.PostID, Source: source,
			Signal: "tls.expires_in_days", Value: &days, Unit: "days", Quality: contract.QualityGood,
			ObservedAt: observedAt, IngestedAt: observedAt, FreshUntil: observedAt.Add(time.Hour),
		})
	}
	return result
}
