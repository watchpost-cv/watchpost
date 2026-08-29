package agentpairing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func TestRotateUsesOverlapAndConfirm(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256([]byte("old-secret"))
	_, err = database.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('install-1','host-one',?)`, old[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(database)
	next, err := service.Rotate(ctx, "install-1", "old-secret", audit.Entry{Action: "test"})
	if err != nil || next == "" {
		t.Fatalf("rotate: %v", err)
	}
	// The old credential remains authoritative; the replacement is pending.
	var storedSecret, pendingHash []byte
	if err = database.DB.QueryRow(`SELECT secret_hash,pending_secret_hash FROM collector_keys WHERE id='install-1'`).Scan(&storedSecret, &pendingHash); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(storedSecret, old[:]) {
		t.Fatal("old credential was invalidated before confirmation")
	}
	expectedPending := sha256.Sum256([]byte(next))
	if !hmac.Equal(pendingHash, expectedPending[:]) {
		t.Fatal("pending credential not stored as a hash")
	}
	// Rotation requires the current active credential.
	if _, err = service.Rotate(ctx, "install-1", "wrong-secret", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("rotate with wrong current credential succeeded")
	}
	// Re-rotating with the active credential replaces the pending slot.
	again, err := service.Rotate(ctx, "install-1", "old-secret", audit.Entry{Action: "test"})
	if err != nil || again == "" {
		t.Fatalf("re-rotate: %v", err)
	}
	expectedPending2 := sha256.Sum256([]byte(again))
	if err = database.DB.QueryRow(`SELECT pending_secret_hash FROM collector_keys WHERE id='install-1'`).Scan(&pendingHash); err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(pendingHash, expectedPending2[:]) {
		t.Fatal("re-rotate did not replace the pending credential")
	}
}

func TestConnectionsRemainDetailsBeneathPost(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"})
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
	_, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = database.DB.Exec(`INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES('install-1','host-one','machine-one','linux/amd64','test',?); INSERT INTO collector_keys(id,post_id,secret_hash,last_seen_at) VALUES('install-1','host-one',X'01',?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	service := New(database)
	if err = service.Revoke(ctx, "install-1", audit.Entry{Action: "test"}); err != nil {
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

func TestPairingHandoffRecoversAfterLostCredential(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	service := New(database)
	request, err := service.Create(ctx, "install-1", "request-secret-that-is-at-least-32-chars-long", "machine", "linux", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Decide(ctx, request.ID, "host-one", true, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	first, err := service.Poll(ctx, request.ID, "request-secret-that-is-at-least-32-chars-long")
	if err != nil || first.Credential == "" {
		t.Fatalf("first poll: %#v %v", first, err)
	}
	// Simulate a crash after the server consumed the request but before the
	// agent persisted the credential: re-poll must reissue a fresh credential.
	second, err := service.Poll(ctx, request.ID, "request-secret-that-is-at-least-32-chars-long")
	if err != nil {
		t.Fatalf("recoverable re-poll failed: %v", err)
	}
	if second.Credential == "" || second.Credential == first.Credential {
		t.Fatalf("re-poll did not reissue a fresh credential: %#v vs %#v", second, first)
	}
	var stored []byte
	if err = database.DB.QueryRow(`SELECT secret_hash FROM collector_keys WHERE id='install-1'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(second.Credential))
	if !hmac.Equal(stored, expected[:]) {
		t.Fatal("stored credential does not match reissued credential")
	}
	oldHash := sha256.Sum256([]byte(first.Credential))
	if hmac.Equal(stored, oldHash[:]) {
		t.Fatal("old lost credential still valid")
	}
}

func TestPairingHandoffRefusesToRotateUsedCredential(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	service := New(database)
	request, err := service.Create(ctx, "install-1", "request-secret-that-is-at-least-32-chars-long", "machine", "linux", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Decide(ctx, request.ID, "host-one", true, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	first, err := service.Poll(ctx, request.ID, "request-secret-that-is-at-least-32-chars-long")
	if err != nil {
		t.Fatal(err)
	}
	// The agent stored and used the credential: mark it seen.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = database.DB.Exec(`UPDATE collector_keys SET last_seen_at=? WHERE id='install-1'`, now); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Poll(ctx, request.ID, "request-secret-that-is-at-least-32-chars-long"); err == nil {
		t.Fatal("re-poll rotated a used credential")
	}
	_ = first
}

func TestAgentSelfUnpairRevokesConnection(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = posts.New(database).Create(ctx, posts.Post{ID: "host-one", Name: "Host one", Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256([]byte("active-credential"))
	if _, err = database.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('install-1','host-one',?); INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES('install-1','host-one','m','linux','test','2026-01-01T00:00:00Z')`, secret[:]); err != nil {
		t.Fatal(err)
	}
	service := New(database)
	if err = service.Unpair(ctx, "install-1", "active-credential", audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	items, err := service.Connections(ctx, "host-one")
	if err != nil || len(items) != 1 || items[0].Status != "revoked" {
		t.Fatalf("connection after self-unpair: %#v %v", items, err)
	}
	// Wrong credential cannot self-unpair.
	if err = service.Unpair(ctx, "install-1", "wrong-credential", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("self-unpair with wrong credential succeeded")
	}
}
