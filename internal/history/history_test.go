package history

import (
	"context"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
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

func TestSurveyGroupsStandardResourceSignals(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"})
	service := ingest.New(db)
	secret, _ := service.Enroll(ctx, "collector", "host-a")
	now := time.Now().UTC()
	for index, signal := range []string{"cpu.percent", "memory.percent", "disk.percent", "temperature.celsius"} {
		value := float64(40 + index)
		err = service.Accept(ctx, secret, ingest.Observation{Version: 1, PostID: "host-a", CollectorID: "collector", ObservedAt: now, Sequence: int64(index + 1), Signal: signal, Value: &value, Unit: "percent", Quality: "good"})
		if err != nil {
			t.Fatal(err)
		}
	}
	series, err := New(db).Survey(ctx, now.Add(-time.Minute), 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 3 {
		t.Fatalf("got %d resource series, want 3", len(series))
	}
}
