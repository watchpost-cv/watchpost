package history

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

func TestSeriesAndRetention(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"})
	service := ingest.New(db)
	now := time.Now().UTC()
	secret, _ := service.Enroll(ctx, "collector", "host-a")
	v := 42.0
	if e = service.Accept(ctx, secret, ingest.Observation{Version: 1, PostID: "host-a", CollectorID: "collector", ObservedAt: now, Sequence: 1, Signal: "cpu", Value: &v, Unit: "percent", Quality: "good"}); e != nil {
		t.Fatal(e)
	}
	h := New(db)
	points, e := h.Series(ctx, "host-a", "cpu", now.Add(-time.Minute), now.Add(time.Minute), 100)
	if e != nil || len(points) != 1 {
		t.Fatalf("%#v %v", points, e)
	}
	n, e := h.Retain(ctx, now.Add(time.Second), 10)
	if e != nil || n != 1 {
		t.Fatalf("%d %v", n, e)
	}
}
