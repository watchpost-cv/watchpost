package actions

import (
	"context"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/auth"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
)

func TestApprovalSeparationIdempotencyAndExecution(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	a, _ := auth.New(db).Setup(ctx, "a@example.com", "correct-horse-battery", "")
	_, _ = db.DB.Exec(`INSERT INTO users(email,password_hash,role,created_at) VALUES('b@example.com',x'00','admin','now')`)
	var b int64
	_ = db.DB.QueryRow(`SELECT id FROM users WHERE email='b@example.com'`).Scan(&b)
	r := New(db)
	_ = r.Register(Definition{Type: "rerun_check", NeedsApproval: true, Validate: func(p map[string]any) error {
		if p["check"] == nil {
			return errors.New("check required")
		}
		return nil
	}, Execute: func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"scheduled": true}, nil
	}})
	id, e := r.Request(ctx, "rerun_check", "", map[string]any{"check": "http"}, a.ID, "key-1")
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Approve(ctx, id, a.ID); e == nil {
		t.Fatal("self approval accepted")
	}
	if e = r.Approve(ctx, id, b); e != nil {
		t.Fatal(e)
	}
	result, e := r.Execute(ctx, id)
	if e != nil || result["scheduled"] != true {
		t.Fatalf("%#v %v", result, e)
	}
	if _, e = r.Request(ctx, "rerun_check", "", map[string]any{"check": "http"}, a.ID, "key-1"); e == nil {
		t.Fatal("duplicate idempotency key accepted")
	}
}
