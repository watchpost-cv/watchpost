package collectorhealth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/ingest"
	"github.com/watchpost-cv/watchpost/internal/posts"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func TestCollectorHealthTransitions(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, t.TempDir())
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"}, audit.Entry{Action: "test"})
	service := ingest.New(db)
	secret, _ := service.Enroll(ctx, "agent-a", "host-a", audit.Entry{Action: "test"})
	health := New(db)
	now := time.Now().UTC()
	health.now = func() time.Time { return now }
	items, _ := health.List(ctx)
	if items[0].Status != "never_connected" {
		t.Fatal(items[0].Status)
	}
	value := 1.0
	observation := ingest.Observation{Version: 1, PostID: "host-a", CollectorID: "agent-a", ObservedAt: now, Sequence: 1, Signal: "collector.up", Value: &value, Unit: "boolean", Quality: "good", Labels: map[string]string{}}
	if err := service.AcceptBatch(ctx, secret, []ingest.Observation{observation}, now); err != nil {
		t.Fatal(err)
	}
	items, _ = health.List(ctx)
	if items[0].Status != "healthy" {
		t.Fatal(items[0].Status)
	}
	health.now = func() time.Time { return now.Add(3 * time.Minute) }
	items, _ = health.List(ctx)
	if items[0].Status != "stale" {
		t.Fatal(items[0].Status)
	}
	health.now = func() time.Time { return now.Add(11 * time.Minute) }
	items, _ = health.List(ctx)
	if items[0].Status != "offline" {
		t.Fatal(items[0].Status)
	}
}

func TestStatusPrecedenceCoversOperationalStates(t *testing.T) {
	now := time.Now().UTC()
	value := func(at time.Time) sql.NullString {
		return sql.NullString{String: at.Format(time.RFC3339Nano), Valid: true}
	}
	none := sql.NullString{}
	tests := []struct {
		name, want                    string
		seen, sent, rejected, revoked sql.NullString
		partial                       bool
	}{
		{"never", "never_connected", none, none, none, none, false},
		{"healthy", "healthy", value(now), value(now), none, none, false},
		{"partial", "partial", value(now), value(now), none, none, true},
		{"skew", "skewed", value(now), value(now.Add(-6 * time.Minute)), none, none, false},
		{"stale", "stale", value(now.Add(-3 * time.Minute)), value(now), none, none, false},
		{"offline", "offline", value(now.Add(-11 * time.Minute)), value(now), none, none, false},
		{"rejected", "rejected", value(now.Add(-time.Minute)), value(now), value(now), none, false},
		{"revoked", "revoked", value(now), value(now), none, value(now), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := status(now, test.seen, test.sent, test.rejected, test.revoked, test.partial); got != test.want {
				t.Fatalf("got %s want %s", got, test.want)
			}
		})
	}
}
