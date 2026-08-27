package rules

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

func TestPendingFiringAcknowledgedResolved(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"})
	engine := New(db)
	if e = engine.Create(ctx, Rule{ID: "cpu-high", PostID: "host-a", Signal: "cpu", Operator: "gt", Threshold: 80, Duration: time.Minute, MissingPolicy: "unknown", Severity: "warning", Enabled: true}); e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v := 90.0
	a, e := engine.Evaluate(ctx, "cpu-high", at, &v, "good")
	if e != nil || a.State != "pending" {
		t.Fatalf("%#v %v", a, e)
	}
	a, e = engine.Evaluate(ctx, "cpu-high", at.Add(time.Minute), &v, "good")
	if e != nil || a.State != "firing" {
		t.Fatalf("%#v %v", a, e)
	}
	if e = engine.Acknowledge(ctx, a.ID, at.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	v = 20
	a, e = engine.Evaluate(ctx, "cpu-high", at.Add(3*time.Minute), &v, "good")
	if e != nil || a.State != "resolved" {
		t.Fatalf("%#v %v", a, e)
	}
}
func TestReplayDeterminism(t *testing.T) {
	run := func(t *testing.T) []string {
		ctx := context.Background()
		db, _ := store.Open(ctx, t.TempDir())
		defer db.Close()
		_, _ = posts.New(db).Create(ctx, posts.Post{ID: "p", Name: "P", Kind: "host"})
		e := New(db)
		_ = e.Create(ctx, Rule{ID: "r", PostID: "p", Signal: "x", Operator: "gt", Threshold: 1, Duration: time.Second, MissingPolicy: "unknown", Severity: "warning", Enabled: true})
		at := time.Unix(100, 0).UTC()
		states := []string{}
		for i, v := range []float64{2, 2, 0} {
			a, _ := e.Evaluate(ctx, "r", at.Add(time.Duration(i)*time.Second), &v, "good")
			states = append(states, a.State)
		}
		return states
	}
	a, b := run(t), run(t)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%v != %v", a, b)
		}
	}
}
