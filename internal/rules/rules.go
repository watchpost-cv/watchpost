package rules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/contract"
	"github.com/watchpost-cv/watchpost/internal/store"
	"strings"
	"time"
)

type Rule struct {
	ID, PostID, Signal, Operator string
	Threshold                    float64
	Duration                     time.Duration
	RecoveryThreshold            *float64
	MissingPolicy, Severity      string
	Enabled                      bool
}

func (e *Engine) ListRules(ctx context.Context, limit int) ([]Rule, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid limit")
	}
	rows, err := e.s.DB.QueryContext(ctx, `SELECT id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled FROM rules ORDER BY post_id,id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Rule{}
	for rows.Next() {
		var item Rule
		var seconds int64
		if err = rows.Scan(&item.ID, &item.PostID, &item.Signal, &item.Operator, &item.Threshold, &seconds, &item.RecoveryThreshold, &item.MissingPolicy, &item.Severity, &item.Enabled); err != nil {
			return nil, err
		}
		item.Duration = time.Duration(seconds) * time.Second
		items = append(items, item)
	}
	return items, rows.Err()
}

func (e *Engine) SetEnabled(ctx context.Context, id string, enabled bool, entry audit.Entry) error {
	tx, err := e.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE rules SET enabled=?,version=version+1 WHERE id=?`, enabled, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("rule not found")
	}
	entry.ObjectType = "rule"
	entry.ObjectID = id
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

type Alert struct {
	ID                  int64  `json:"id"`
	RuleID              string `json:"rule_id"`
	PostID              string `json:"post_id"`
	State               string `json:"state"`
	Severity            string `json:"severity"`
	OpenedAt, UpdatedAt time.Time
	Value               *float64
}
type Engine struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Engine { return &Engine{s: s, now: time.Now} }
func (e *Engine) Create(ctx context.Context, r Rule, entry audit.Entry) error {
	if r.ID == "" || r.PostID == "" || r.Signal == "" || !map[string]bool{"gt": true, "gte": true, "lt": true, "lte": true}[r.Operator] || !map[string]bool{"unknown": true, "healthy": true, "firing": true}[r.MissingPolicy] || r.Duration < 0 {
		return errors.New("invalid rule")
	}
	tx, err := e.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO rules(id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled) VALUES(?,?,?,?,?,?,?,?,?,?)`, r.ID, r.PostID, r.Signal, r.Operator, r.Threshold, int64(r.Duration/time.Second), r.RecoveryThreshold, r.MissingPolicy, r.Severity, r.Enabled); err != nil {
		return err
	}
	entry.ObjectType = "rule"
	entry.ObjectID = r.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) Evaluate(ctx context.Context, ruleID string, at time.Time, value *float64, quality string) (Alert, error) {
	tx, err := e.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback()
	var r Rule
	var seconds int64
	var maintenance bool
	err = tx.QueryRowContext(ctx, `SELECT r.id,r.post_id,r.signal,r.operator,r.threshold,r.duration_seconds,r.recovery_threshold,r.missing_policy,r.severity,r.enabled,p.maintenance FROM rules r JOIN posts p ON p.id=r.post_id WHERE r.id=?`, ruleID).Scan(&r.ID, &r.PostID, &r.Signal, &r.Operator, &r.Threshold, &seconds, &r.RecoveryThreshold, &r.MissingPolicy, &r.Severity, &r.Enabled, &maintenance)
	if err != nil {
		return Alert{}, err
	}
	r.Duration = time.Duration(seconds) * time.Second
	breached := value != nil && quality == "good" && compare(*value, r.Operator, r.Threshold)
	if (value == nil || quality != "good") && r.MissingPolicy == "firing" {
		breached = true
	}
	desired := "resolved"
	if breached {
		desired = "pending"
		if r.Duration == 0 {
			desired = "firing"
		}
	}
	if maintenance && breached {
		desired = "suppressed"
	}
	var current Alert
	var opened, updated string
	err = tx.QueryRowContext(ctx, `SELECT id,state,opened_at,updated_at,value FROM alerts WHERE rule_id=? AND post_id=? ORDER BY id DESC LIMIT 1`, r.ID, r.PostID).Scan(&current.ID, &current.State, &opened, &updated, &current.Value)
	if err == nil {
		current.OpenedAt, _ = time.Parse(time.RFC3339Nano, opened)
		current.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if value != nil && r.RecoveryThreshold != nil && (current.State == "firing" || current.State == "acknowledged") {
			breached = !recovered(*value, r.Operator, *r.RecoveryThreshold)
		}
		if maintenance && breached {
			desired = "suppressed"
		} else if breached && desired == "resolved" {
			desired = "pending"
		}
		if breached && (current.State == "pending" || current.State == "firing" || current.State == "acknowledged") {
			desired = current.State
			if current.State == "pending" && at.Sub(current.OpenedAt) >= r.Duration {
				desired = "firing"
			}
		}
		if !breached && current.State == "resolved" {
			desired = "resolved"
		}
		if desired == current.State {
			current.Value = value
			return current, tx.Commit()
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Alert{}, err
	}
	if !breached && errors.Is(err, sql.ErrNoRows) {
		return Alert{RuleID: r.ID, PostID: r.PostID, State: "resolved", Severity: r.Severity, UpdatedAt: at}, tx.Commit()
	}
	openedAt := at
	if current.ID != 0 && breached {
		openedAt = current.OpenedAt
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at,resolved_at,value) VALUES(?,?,?,?,?,?,?,?)`, r.ID, r.PostID, desired, r.Severity, openedAt.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), nullableTime(desired == "resolved", at), value)
	if err != nil {
		return Alert{}, err
	}
	id, _ := result.LastInsertId()
	if err = tx.Commit(); err != nil {
		return Alert{}, err
	}
	return Alert{ID: id, RuleID: r.ID, PostID: r.PostID, State: desired, Severity: r.Severity, OpenedAt: openedAt, UpdatedAt: at, Value: value}, nil
}
func (e *Engine) Acknowledge(ctx context.Context, id int64, at time.Time, entry audit.Entry) error {
	tx, err := e.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE alerts SET state='acknowledged',acknowledged_at=?,updated_at=? WHERE id=? AND state='firing'`, at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("alert is not firing")
	}
	entry.ObjectType = "alert"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) EvaluateObservation(ctx context.Context, postID, signal string, at time.Time, value *float64, quality string) ([]Alert, error) {
	signals := []string{signal}
	for legacy, canonical := range contract.LegacySignalAliases {
		if canonical == signal {
			signals = append(signals, legacy)
		}
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(signals)), ",")
	args := make([]any, 0, len(signals)+1)
	args = append(args, postID)
	for _, item := range signals {
		args = append(args, item)
	}
	rows, err := e.s.DB.QueryContext(ctx, `SELECT id FROM rules WHERE post_id=? AND signal IN (`+placeholders+`) AND enabled=1 ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	alerts := []Alert{}
	for _, id := range ids {
		alert, err := e.Evaluate(ctx, id, at, value, quality)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}
func (e *Engine) ListAlerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid limit")
	}
	rows, err := e.s.DB.QueryContext(ctx, `SELECT id,rule_id,post_id,state,severity,opened_at,updated_at,value FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Alert{}
	for rows.Next() {
		var a Alert
		var opened, updated string
		if err = rows.Scan(&a.ID, &a.RuleID, &a.PostID, &a.State, &a.Severity, &opened, &updated, &a.Value); err != nil {
			return nil, err
		}
		a.OpenedAt, _ = time.Parse(time.RFC3339Nano, opened)
		a.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		items = append(items, a)
	}
	return items, rows.Err()
}
func compare(v float64, op string, t float64) bool {
	switch op {
	case "gt":
		return v > t
	case "gte":
		return v >= t
	case "lt":
		return v < t
	case "lte":
		return v <= t
	}
	return false
}
func recovered(v float64, op string, t float64) bool {
	if op == "gt" || op == "gte" {
		return v < t
	}
	return v > t
}
func nullableTime(ok bool, t time.Time) any {
	if ok {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return nil
}
