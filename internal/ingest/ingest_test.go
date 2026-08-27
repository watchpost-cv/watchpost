package ingest

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

func TestAuthenticatedIngestRejectsReplayAndClock(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, e = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"})
	if e != nil {
		t.Fatal(e)
	}
	s := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	secret, e := s.Enroll(ctx, "collector-a", "host-a")
	if e != nil {
		t.Fatal(e)
	}
	o := Observation{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 1, Signal: "cpu.utilization", Quality: "good"}
	if e = s.Accept(ctx, secret, o); e != nil {
		t.Fatal(e)
	}
	if e = s.Accept(ctx, secret, o); e == nil {
		t.Fatal("replay accepted")
	}
	o.Sequence = 2
	o.ObservedAt = now.Add(6 * time.Minute)
	if e = s.Accept(ctx, secret, o); e == nil {
		t.Fatal("future observation accepted")
	}
}

func FuzzObservationValidation(f *testing.F) {
	f.Add("signal", "good", int64(1))
	f.Add("", "bad-quality", int64(-1))
	f.Fuzz(func(t *testing.T, signal, quality string, sequence int64) {
		db, err := store.Open(context.Background(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, err = posts.New(db).Create(context.Background(), posts.Post{ID: "host-a", Name: "A", Kind: "host"})
		if err != nil {
			t.Fatal(err)
		}
		service := New(db)
		now := time.Now().UTC()
		service.now = func() time.Time { return now }
		secret, err := service.Enroll(context.Background(), "collector-a", "host-a")
		if err != nil {
			t.Fatal(err)
		}
		_ = service.Accept(context.Background(), secret, Observation{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: sequence, Signal: signal, Quality: quality})
	})
}
