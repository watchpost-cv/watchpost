package auth

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/store"
)

func testDB(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBootstrapTokenRequiredForSetup(t *testing.T) {
	ctx := context.Background()
	m := New(testDB(t))
	m.SetBootstrapTokenRequired(true)
	token, err := m.GenerateBootstrapToken(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Setup(ctx, "admin@example.com", "correct-horse-battery", ""); err == nil {
		t.Fatal("setup without bootstrap token succeeded")
	}
	if _, err = m.Setup(ctx, "admin@example.com", "correct-horse-battery", "wrong-token"); err == nil {
		t.Fatal("setup with wrong bootstrap token succeeded")
	}
	user, err := m.Setup(ctx, "admin@example.com", "correct-horse-battery", token)
	if err != nil {
		t.Fatalf("setup with token failed: %v", err)
	}
	if user.Role != "admin" {
		t.Fatalf("role=%s want admin", user.Role)
	}
	if _, err = m.Setup(ctx, "other@example.com", "correct-horse-battery", token); err == nil {
		t.Fatal("second setup succeeded")
	}
}

func TestBootstrapTokenExpiryAndHashing(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	m := New(db)
	m.SetBootstrapTokenRequired(true)
	if err := m.SetBootstrapToken(ctx, "my-operator-token", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Setup(ctx, "admin@example.com", "correct-horse-battery", "my-operator-token"); err == nil {
		t.Fatal("setup with expired token succeeded")
	}
	// Only a SHA-256 hash of the token is persisted, never the raw value.
	expected := sha256.Sum256([]byte("my-operator-token"))
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM bootstrap_tokens WHERE token_hash=?`, expected[:]).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("hashed token rows=%d want 1", count)
	}
	var rawRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM bootstrap_tokens`).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if rawRows != 1 {
		t.Fatalf("bootstrap token rows=%d want 1", rawRows)
	}
}

func TestLoopbackSetupRemainsDirect(t *testing.T) {
	ctx := context.Background()
	m := New(testDB(t))
	// Default: no token required (loopback).
	if m.BootstrapTokenRequired() {
		t.Fatal("loopback setup unexpectedly requires a token")
	}
	if _, err := m.Setup(ctx, "admin@example.com", "correct-horse-battery", ""); err != nil {
		t.Fatalf("direct loopback setup failed: %v", err)
	}
}
