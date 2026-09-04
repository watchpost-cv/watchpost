package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
	"sync"
	"time"
)

type Definition struct {
	Type          string
	NeedsApproval bool
	Validate      func(map[string]any) error
	Execute       func(context.Context, string, map[string]any) (map[string]any, error)
}
type Registry struct {
	s           *store.Store
	mu          sync.RWMutex
	definitions map[string]Definition
	now         func() time.Time
}
type RequestRecord struct {
	ID          int64          `json:"id"`
	Type        string         `json:"type"`
	PostID      string         `json:"post_id"`
	Parameters  map[string]any `json:"parameters"`
	State       string         `json:"state"`
	RequestedBy int64          `json:"requested_by"`
	ApprovedBy  *int64         `json:"approved_by"`
	RequestedAt time.Time      `json:"requested_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Result      map[string]any `json:"result"`
}

func (r *Registry) List(ctx context.Context, limit int) ([]RequestRecord, error) {
	if limit < 1 || limit > 500 {
		return nil, errors.New("invalid limit")
	}
	rows, err := r.s.DB.QueryContext(ctx, `SELECT id,type,COALESCE(post_id,''),parameters_json,state,requested_by,approved_by,requested_at,updated_at,result_json FROM action_requests ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RequestRecord{}
	for rows.Next() {
		var v RequestRecord
		var params, result, requested, updated string
		if err = rows.Scan(&v.ID, &v.Type, &v.PostID, &params, &v.State, &v.RequestedBy, &v.ApprovedBy, &requested, &updated, &result); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(params), &v.Parameters)
		_ = json.Unmarshal([]byte(result), &v.Result)
		v.RequestedAt, _ = time.Parse(time.RFC3339Nano, requested)
		v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		items = append(items, v)
	}
	return items, rows.Err()
}

func New(s *store.Store) *Registry {
	return &Registry{s: s, definitions: map[string]Definition{}, now: time.Now}
}
func (r *Registry) Register(d Definition) error {
	if d.Type == "" || d.Validate == nil || d.Execute == nil {
		return errors.New("invalid action definition")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.definitions[d.Type]; exists {
		return errors.New("duplicate action")
	}
	r.definitions[d.Type] = d
	return nil
}
func (r *Registry) Request(ctx context.Context, actionType, postID string, parameters map[string]any, userID int64, key string, entry audit.Entry) (int64, error) {
	r.mu.RLock()
	d, ok := r.definitions[actionType]
	r.mu.RUnlock()
	if !ok || key == "" {
		return 0, errors.New("unknown action or missing idempotency key")
	}
	if err := d.Validate(parameters); err != nil {
		return 0, err
	}
	encoded, _ := json.Marshal(parameters)
	state := "approved"
	if d.NeedsApproval {
		state = "pending"
	}
	now := r.now().UTC().Format(time.RFC3339Nano)
	tx, err := r.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO action_requests(type,post_id,parameters_json,state,requested_by,requested_at,updated_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?)`, actionType, nullable(postID), string(encoded), state, userID, now, now, key)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	entry.ActorID = userID
	entry.ObjectType = "action"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}
func (r *Registry) Approve(ctx context.Context, id, approver int64, entry audit.Entry) error {
	tx, err := r.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE action_requests SET state='approved',approved_by=?,updated_at=? WHERE id=? AND state='pending' AND requested_by<>?`, approver, r.now().UTC().Format(time.RFC3339Nano), id, approver)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("action cannot be approved")
	}
	entry.ActorID = approver
	entry.ObjectType = "action"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *Registry) Execute(ctx context.Context, id int64, entry audit.Entry) (map[string]any, error) {
	var kind, post, encoded, state string
	if err := r.s.DB.QueryRowContext(ctx, `SELECT type,COALESCE(post_id,''),parameters_json,state FROM action_requests WHERE id=?`, id).Scan(&kind, &post, &encoded, &state); err != nil {
		return nil, err
	}
	if state != "approved" {
		return nil, errors.New("action is not approved")
	}
	claim, err := r.s.DB.ExecContext(ctx, `UPDATE action_requests SET state='executing',updated_at=? WHERE id=? AND state='approved'`, r.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return nil, err
	}
	claimed, _ := claim.RowsAffected()
	if claimed != 1 {
		return nil, errors.New("action execution already claimed")
	}
	r.mu.RLock()
	d, ok := r.definitions[kind]
	r.mu.RUnlock()
	if !ok {
		return nil, errors.New("action definition unavailable")
	}
	params := map[string]any{}
	_ = json.Unmarshal([]byte(encoded), &params)
	result, err := d.Execute(ctx, post, params)
	newState := "completed"
	if err != nil {
		newState = "failed"
		result = map[string]any{"error": err.Error()}
	}
	output, _ := json.Marshal(result)
	tx, txErr := r.s.DB.BeginTx(ctx, nil)
	if txErr != nil {
		return nil, txErr
	}
	defer tx.Rollback()
	if _, updateErr := tx.ExecContext(ctx, `UPDATE action_requests SET state=?,result_json=?,updated_at=? WHERE id=? AND state='executing'`, newState, string(output), r.now().UTC().Format(time.RFC3339Nano), id); updateErr != nil {
		return nil, updateErr
	}
	entry.ObjectType = "action"
	entry.ObjectID = fmt.Sprint(id)
	if err := audit.Insert(ctx, tx, entry); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, err
}
func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
