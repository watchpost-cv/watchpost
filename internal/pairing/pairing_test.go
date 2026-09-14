package pairing

import (
	"context"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/posts"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func TestPairingTokenIsShortLivedAndSingleUse(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	token, err := service.Create(ctx, "host-a", 5*time.Minute, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.Consume(ctx, token.Token, "agent-a")
	if err != nil || enrollment.PostID != "host-a" || enrollment.Secret == "" {
		t.Fatalf("%#v %v", enrollment, err)
	}
	if _, err = service.Consume(ctx, token.Token, "agent-b"); err == nil {
		t.Fatal("reused token")
	}
	rotation, err := service.Create(ctx, "host-a", 5*time.Minute, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.Consume(ctx, rotation.Token, "agent-a")
	if err != nil || rotated.Secret == enrollment.Secret {
		t.Fatalf("collector credential was not rotated: %#v %v", rotated, err)
	}
	expired, _ := service.Create(ctx, "host-a", time.Minute, audit.Entry{Action: "test"})
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err = service.Consume(ctx, expired.Token, "agent-c"); err == nil {
		t.Fatal("accepted expired token")
	}
}

func TestRepairClearsStaleObservationSequenceSpace(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"}, audit.Entry{Action: "test"})
	service := New(db)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	token, err := service.Create(ctx, "host-a", 5*time.Minute, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.Consume(ctx, token.Token, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	for sequence, signal := range map[int]string{1: "cpu.percent", 2: "memory.percent"} {
		if _, err = db.DB.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES('host-a','agent-a',?,?,?,?,1,'percent','good','{}')`, now, now, sequence, signal); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.DB.Exec(`UPDATE collector_keys SET last_sequence=2 WHERE id='agent-a'`); err != nil {
		t.Fatal(err)
	}

	// Re-pair the same installation. The prior observation rows share the
	// UNIQUE(collector_id,sequence,signal) space the fresh sequence restart
	// will reuse, so they must be purged together with last_sequence=0.
	rotation, err := service.Create(ctx, "host-a", 5*time.Minute, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, rotation.Token, "agent-a"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.DB.QueryRow(`SELECT COUNT(*) FROM observations WHERE collector_id='agent-a'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale observations survived re-pair: count=%d err=%v", count, err)
	}
	var last int64
	if err = db.DB.QueryRow(`SELECT last_sequence FROM collector_keys WHERE id='agent-a'`).Scan(&last); err != nil || last != 0 {
		t.Fatalf("last_sequence=%d err=%v", last, err)
	}
	_ = enrollment
}
