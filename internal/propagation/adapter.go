package propagation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/store"
)

type Adapter struct {
	db  *sql.DB
	now func() time.Time
}

func New(st *store.Store) *Adapter { return &Adapter{db: st.DB, now: time.Now} }
func (a *Adapter) Kinds() []core.KindDescriptor {
	return []core.KindDescriptor{{Kind: "alert-policy", Label: "Alert policies", SchemaVersion: 1, Reversible: true}, {Kind: "monitor", Label: "Monitors", SchemaVersion: 1, Reversible: true}, {Kind: "notification-config", Label: "Notification routes", SchemaVersion: 1, Reversible: true}}
}
func selected(kinds []string, kind string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

type monitorPayload struct {
	PostID          string `json:"post_id"`
	Kind            string `json:"kind"`
	Address         string `json:"address"`
	ServerName      string `json:"server_name,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
}
type alertPayload struct {
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
type notificationPayload struct {
	Kind        string `json:"kind"`
	Destination string `json:"destination"`
	Enabled     bool   `json:"enabled"`
}

func envelope(kind, id string, revision int64, source, target string, actor core.Actor, payload any, secrets []core.SecretRef, deps []string) (core.Envelope, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return core.Envelope{}, err
	}
	e := core.Envelope{Kind: kind, ID: id, SchemaVersion: 1, Revision: revision, SourceNode: source, CreatedAt: time.Now().UTC(), Target: target, Conflict: core.ConflictSourceWins, Actor: actor, Payload: b, Secrets: secrets, Dependencies: deps}
	if err = e.Validate(); err != nil {
		return core.Envelope{}, err
	}
	return e, nil
}
func (a *Adapter) Export(ctx context.Context, kinds []string, actor core.Actor, target string) ([]core.Envelope, error) {
	source := "watchpost-local"
	out := []core.Envelope{}
	if selected(kinds, "monitor") {
		rows, err := a.db.QueryContext(ctx, `SELECT id,post_id,kind,address,server_name,interval_seconds,enabled FROM check_schedules ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var p monitorPayload
			var enabled int
			if err := rows.Scan(&id, &p.PostID, &p.Kind, &p.Address, &p.ServerName, &p.IntervalSeconds, &enabled); err != nil {
				rows.Close()
				return nil, err
			}
			p.Enabled = enabled != 0
			e, err := envelope("monitor", id, 1, source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "monitor.update"}, p, nil, []string{"post:" + p.PostID})
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	if selected(kinds, "alert-policy") {
		rows, err := a.db.QueryContext(ctx, `SELECT id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version FROM rules ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var p alertPayload
			var rec sql.NullFloat64
			var enabled int
			var version int64
			if err := rows.Scan(&id, &p.PostID, &p.Signal, &p.Operator, &p.Threshold, &p.DurationSeconds, &rec, &p.MissingPolicy, &p.Severity, &enabled, &version); err != nil {
				rows.Close()
				return nil, err
			}
			if rec.Valid {
				v := rec.Float64
				p.RecoveryThreshold = &v
			}
			p.Enabled = enabled != 0
			e, err := envelope("alert-policy", id, max1(version), source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "alert.update"}, p, nil, []string{"post:" + p.PostID})
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	if selected(kinds, "notification-config") {
		rows, err := a.db.QueryContext(ctx, `SELECT id,kind,destination,secret,enabled FROM notification_routes ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, secret string
			var p notificationPayload
			var enabled int
			if err := rows.Scan(&id, &p.Kind, &p.Destination, &secret, &enabled); err != nil {
				rows.Close()
				return nil, err
			}
			p.Enabled = enabled != 0
			refs := []core.SecretRef{}
			if secret != "" {
				refs = append(refs, core.SecretRef{Name: "watchpost.notification-route." + id, Required: true})
			}
			e, err := envelope("notification-config", id, 1, source, target, core.Actor{Kind: actor.Kind, ID: actor.ID, Permission: "notification.update"}, p, refs, nil)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].ID < out[j].ID
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}
func max1(v int64) int64 {
	if v < 1 {
		return 1
	}
	return v
}
func (a *Adapter) Snapshot(ctx context.Context, kinds []string) (map[string]core.ObjectState, error) {
	envs, err := a.Export(ctx, kinds, core.Actor{}, "local")
	if err != nil {
		return nil, err
	}
	out := map[string]core.ObjectState{}
	for _, e := range envs {
		out[e.Kind+"/"+e.ID] = core.ObjectState{Existing: core.Existing{Kind: e.Kind, ID: e.ID, Digest: e.Digest, Revision: e.Revision}, Payload: e.Payload, Reversible: true}
	}
	return out, nil
}
func (a *Adapter) TargetState(ctx context.Context, src []core.Envelope, actor core.Actor) (core.TargetState, error) {
	snap, err := a.Snapshot(ctx, nil)
	if err != nil {
		return core.TargetState{}, err
	}
	existing := map[string]core.Existing{}
	for k, s := range snap {
		existing[k] = s.Existing
	}
	deps := map[string]bool{}
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM posts`)
	if err != nil {
		return core.TargetState{}, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return core.TargetState{}, err
		}
		deps["post:"+id] = true
	}
	rows.Close()
	secrets := core.MapSecrets{}
	for _, e := range src {
		if e.Kind != "notification-config" {
			continue
		}
		var secret string
		err := a.db.QueryRowContext(ctx, `SELECT secret FROM notification_routes WHERE id=?`, e.ID).Scan(&secret)
		if err == nil && secret != "" {
			secrets["watchpost.notification-route."+e.ID] = true
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return core.TargetState{}, err
		}
	}
	perms := map[string]bool{}
	for _, e := range src {
		if e.Actor.Permission != "" {
			perms[e.Actor.Permission] = true
		}
	}
	return core.TargetState{Existing: existing, SupportedSchemas: map[string]int{"monitor": 1, "alert-policy": 1, "notification-config": 1}, Dependencies: deps, Secrets: secrets, Permissions: perms}, nil
}
func (a *Adapter) Apply(ctx context.Context, e core.Envelope) (core.AppliedRevision, error) {
	if err := ValidateEnvelope(e); err != nil {
		return core.AppliedRevision{}, err
	}
	// Single authoritative replicated write path: when the replicated adapter is
	// enabled, propagation must not directly mutate replicated tables. It must
	// route through the replicated adapter or be rejected here.
	if replicated.IsReplicatedEnabled() {
		return core.AppliedRevision{}, errors.New("propagation apply rejected: replicated state must be mutated through the replicated adapter")
	}
	switch e.Kind {
	case "monitor":
		var p monitorPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var exists int
		_ = a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM check_schedules WHERE id=?`, e.ID).Scan(&exists)
		_, err := a.db.ExecContext(ctx, `INSERT INTO check_schedules(id,post_id,kind,address,server_name,interval_seconds,enabled,next_run_at,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET post_id=excluded.post_id,kind=excluded.kind,address=excluded.address,server_name=excluded.server_name,interval_seconds=excluded.interval_seconds,enabled=excluded.enabled`, e.ID, p.PostID, p.Kind, p.Address, p.ServerName, p.IntervalSeconds, boolInt(p.Enabled), a.now().UTC().Format(time.RFC3339Nano), a.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, Before: int64(exists), After: e.Revision, Reversible: true}, nil
	case "alert-policy":
		var p alertPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var before int64
		_ = a.db.QueryRowContext(ctx, `SELECT version FROM rules WHERE id=?`, e.ID).Scan(&before)
		_, err := a.db.ExecContext(ctx, `INSERT INTO rules(id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET post_id=excluded.post_id,signal=excluded.signal,operator=excluded.operator,threshold=excluded.threshold,duration_seconds=excluded.duration_seconds,recovery_threshold=excluded.recovery_threshold,missing_policy=excluded.missing_policy,severity=excluded.severity,enabled=excluded.enabled,version=excluded.version`, e.ID, p.PostID, p.Signal, p.Operator, p.Threshold, p.DurationSeconds, p.RecoveryThreshold, p.MissingPolicy, p.Severity, boolInt(p.Enabled), e.Revision)
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, Before: before, After: e.Revision, Reversible: true}, nil
	case "notification-config":
		var p notificationPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return core.AppliedRevision{}, err
		}
		var secret string
		err := a.db.QueryRowContext(ctx, `SELECT secret FROM notification_routes WHERE id=?`, e.ID).Scan(&secret)
		if errors.Is(err, sql.ErrNoRows) {
			if len(e.Secrets) > 0 {
				return core.AppliedRevision{}, fmt.Errorf("notification route %s requires destination secret", e.ID)
			}
			secret = ""
		} else if err != nil {
			return core.AppliedRevision{}, err
		}
		_, err = a.db.ExecContext(ctx, `INSERT INTO notification_routes(id,kind,destination,secret,enabled) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,destination=excluded.destination,enabled=excluded.enabled`, e.ID, p.Kind, p.Destination, secret, boolInt(p.Enabled))
		if err != nil {
			return core.AppliedRevision{}, err
		}
		return core.AppliedRevision{Kind: e.Kind, ID: e.ID, After: e.Revision, Reversible: true}, nil
	default:
		return core.AppliedRevision{}, fmt.Errorf("unsupported kind %q", e.Kind)
	}
}
func (a *Adapter) Restore(ctx context.Context, s core.ObjectState) error {
	if s.Existing.Revision == 0 && len(s.Payload) == 0 {
		_, err := a.db.ExecContext(ctx, deleteSQL(s.Existing.Kind), s.Existing.ID)
		return err
	}
	e := core.Envelope{Kind: s.Existing.Kind, ID: s.Existing.ID, SchemaVersion: 1, Revision: max1(s.Existing.Revision), SourceNode: "rollback", Target: "local", Conflict: core.ConflictSourceWins, Payload: s.Payload}
	switch e.Kind {
	case "monitor":
		e.Actor.Permission = "monitor.update"
	case "alert-policy":
		e.Actor.Permission = "alert.update"
	case "notification-config":
		e.Actor.Permission = "notification.update"
	}
	_, err := a.Apply(ctx, e)
	return err
}
func deleteSQL(kind string) string {
	switch kind {
	case "monitor":
		return `DELETE FROM check_schedules WHERE id=?`
	case "alert-policy":
		return `DELETE FROM rules WHERE id=?`
	case "notification-config":
		return `DELETE FROM notification_routes WHERE id=?`
	default:
		return `SELECT 1 WHERE ?=''`
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
