package agentpairing

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func TestRotateCredentialInvalidatesPreviousSecret(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256([]byte("old-secret"))
	_, err = database.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('install-1','host-one',?)`, old[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(database)
	next, err := service.Rotate(ctx, "install-1", "old-secret")
	if err != nil || next == "" {
		t.Fatalf("rotate: %v", err)
	}
	if _, err = service.Rotate(ctx, "install-1", "old-secret"); err == nil {
		t.Fatal("old credential still valid")
	}
}

func TestConnectionsRemainDetailsBeneathPost(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = database.DB.Exec(`INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES('install-1','host-one','machine-one','linux/amd64','test',?); INSERT INTO collector_keys(id,post_id,secret_hash,last_seen_at) VALUES('install-1','host-one',X'01',?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	items, err := New(database).Connections(ctx, "host-one")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].PostID != "host-one" || items[0].Status != "healthy" {
		t.Fatalf("unexpected connections: %#v", items)
	}
}

func TestRevokeEndsAgentAuthority(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = database.DB.Exec(`INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES('install-1','host-one','machine-one','linux/amd64','test',?); INSERT INTO collector_keys(id,post_id,secret_hash,last_seen_at) VALUES('install-1','host-one',X'01',?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	service := New(database)
	if err = service.Revoke(ctx, "install-1"); err != nil {
		t.Fatal(err)
	}
	items, err := service.Connections(ctx, "host-one")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != "revoked" {
		t.Fatalf("unexpected status: %#v", items)
	}
}
