package pairing

import (
	"context"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func TestPairingTokenIsShortLivedAndSingleUse(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "host-a", Name: "A", Kind: "host"})
	service := New(db)
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	token, err := service.Create(ctx, "host-a", 5*time.Minute)
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
	rotation, err := service.Create(ctx, "host-a", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.Consume(ctx, rotation.Token, "agent-a")
	if err != nil || rotated.Secret == enrollment.Secret {
		t.Fatalf("collector credential was not rotated: %#v %v", rotated, err)
	}
	expired, _ := service.Create(ctx, "host-a", time.Minute)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err = service.Consume(ctx, expired.Token, "agent-c"); err == nil {
		t.Fatal("accepted expired token")
	}
}
