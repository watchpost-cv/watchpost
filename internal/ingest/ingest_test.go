package ingest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/audit"
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
	_, e = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"}, audit.Entry{Action: "test"})
	if e != nil {
		t.Fatal(e)
	}
	s := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	secret, e := s.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
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

func TestAcceptBatchIsAtomicAndContiguous(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "Host", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	secret, _ := service.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
	now := time.Now().UTC()
	value := 50.0
	items := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 1, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}, {Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 2, Signal: "memory.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, items, now); err != nil {
		t.Fatal(err)
	}
	items[0].Sequence, items[1].Sequence = 3, 5
	if service.AcceptBatch(ctx, secret, items, now) == nil {
		t.Fatal("accepted sequence gap")
	}
	var count int
	if err = db.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
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
		_, err = posts.New(db).Create(context.Background(), posts.Post{ID: "host-a", Name: "A", Kind: "host"}, audit.Entry{Action: "test"})
		if err != nil {
			t.Fatal(err)
		}
		service := New(db)
		now := time.Now().UTC()
		service.now = func() time.Time { return now }
		secret, err := service.Enroll(context.Background(), "collector-a", "host-a", audit.Entry{Action: "test"})
		if err != nil {
			t.Fatal(err)
		}
		_ = service.Accept(context.Background(), secret, Observation{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: sequence, Signal: signal, Quality: quality})
	})
}

func TestPendingCredentialPromotedOnFirstUse(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "Host", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	oldSecret, _ := service.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
	pendingRaw := "pending-replacement-credential"
	pendingHash := sha256.Sum256([]byte(pendingRaw))
	if _, err = db.DB.Exec(`UPDATE collector_keys SET pending_secret_hash=?,pending_expires_at=? WHERE id='collector-a'`, pendingHash[:], now.Add(10*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	value := 50.0
	batch := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 1, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	// The pending credential authenticates and is promoted on first use.
	if err = service.AcceptBatch(ctx, pendingRaw, batch, now); err != nil {
		t.Fatalf("pending credential rejected: %v", err)
	}
	var stored []byte
	if err = db.DB.QueryRow(`SELECT secret_hash,pending_secret_hash FROM collector_keys WHERE id='collector-a'`).Scan(&stored, new([]byte)); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(stored, pendingHash[:]) {
		t.Fatal("pending credential was not promoted to active")
	}
	// The old credential no longer authenticates after promotion.
	if err = service.AcceptBatch(ctx, oldSecret, batch, now); err == nil {
		t.Fatal("old credential still accepted after promotion")
	}
}

func TestExpiredPendingCredentialDoesNotInvalidateOld(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "Host", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	oldSecret, _ := service.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
	pendingRaw := "expired-pending-replacement"
	pendingHash := sha256.Sum256([]byte(pendingRaw))
	if _, err = db.DB.Exec(`UPDATE collector_keys SET pending_secret_hash=?,pending_expires_at=? WHERE id='collector-a'`, pendingHash[:], now.Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	value := 50.0
	batch := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 1, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, pendingRaw, batch, now); err == nil {
		t.Fatal("expired pending credential accepted")
	}
	// The old credential remains authoritative.
	if err = service.AcceptBatch(ctx, oldSecret, batch, now); err != nil {
		t.Fatalf("old credential rejected after expired replacement: %v", err)
	}
}

func TestIngestRateBudgetRejectsOverflow(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "Host", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	service.SetIngestRate(3)
	secret, _ := service.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
	value := 50.0
	batch := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 1, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, batch, now); err != nil {
		t.Fatalf("first batch rejected: %v", err)
	}
	second := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 2, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, second, now); err != nil {
		t.Fatalf("second batch rejected: %v", err)
	}
	third := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 3, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, third, now); err != nil {
		t.Fatalf("third batch rejected: %v", err)
	}
	fourth := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now, Sequence: 4, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, fourth, now); err == nil {
		t.Fatal("batch beyond the per-minute budget was accepted")
	}
	// A new minute resets the budget.
	service.now = func() time.Time { return now.Add(time.Minute) }
	next := []Observation{{Version: 1, PostID: "host-a", CollectorID: "collector-a", ObservedAt: now.Add(time.Minute), Sequence: 4, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	if err = service.AcceptBatch(ctx, secret, next, now.Add(time.Minute)); err != nil {
		t.Fatalf("batch in the next minute rejected: %v", err)
	}
}
