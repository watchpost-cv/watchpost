package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/watchpost-ops/watchpost/internal/devices"
	"github.com/watchpost-ops/watchpost/internal/secrets"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOnlineBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := testStore(t)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('p','Host','host','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "backup.db")
	if err := Create(ctx, db, output, ""); err != nil {
		t.Fatalf("online backup failed: %v", err)
	}
	restoredDir := filepath.Join(t.TempDir(), "restored")
	if err := Restore(ctx, restoredDir, output, "", false); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	restored, err := store.Open(ctx, restoredDir)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var count int
	if err := restored.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='p'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored post missing: %d %v", count, err)
	}
}

func TestEncryptedBackupRequiresPassphrase(t *testing.T) {
	ctx := context.Background()
	db := testStore(t)
	output := filepath.Join(t.TempDir(), "backup.wpbk")
	if err := Create(ctx, db, output, "a-strong-backup-passphrase"); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !isEncrypted(blob) {
		t.Fatal("backup is not encrypted")
	}
	if blob[0] == 'S' {
		t.Fatal("plaintext SQLite leaked into encrypted backup")
	}
	// Wrong passphrase fails closed.
	restoredDir := filepath.Join(t.TempDir(), "restored")
	if err := Restore(ctx, restoredDir, output, "wrong-passphrase-value", false); err == nil {
		t.Fatal("restore with wrong passphrase succeeded")
	}
	// Correct passphrase restores.
	if err := Restore(ctx, restoredDir, output, "a-strong-backup-passphrase", false); err != nil {
		t.Fatalf("restore with correct passphrase failed: %v", err)
	}
	// Short passphrases are refused.
	short := filepath.Join(t.TempDir(), "short.db")
	if err := Create(ctx, db, short, "tooshort"); err == nil {
		t.Fatal("short backup passphrase accepted")
	}
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	ctx := context.Background()
	db := testStore(t)
	// Simulate a newer database by writing a schema version beyond support.
	if _, err := db.DB.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(99,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "newer.db")
	if err := Create(ctx, db, output, ""); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, filepath.Join(t.TempDir(), "restored"), output, "", false); err == nil {
		t.Fatal("restore of a newer-schema database succeeded")
	}
}

func TestRestoreRefusesExistingDatabaseWithoutForce(t *testing.T) {
	ctx := context.Background()
	db := testStore(t)
	output := filepath.Join(t.TempDir(), "backup.db")
	if err := Create(ctx, db, output, ""); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if _, err := store.Open(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, dataDir, output, "", false); err == nil {
		t.Fatal("restore over an existing database without --force succeeded")
	}
	if err := Restore(ctx, dataDir, output, "", true); err != nil {
		t.Fatalf("forced restore failed: %v", err)
	}
}

func TestRekeyReencryptsDeviceCredentials(t *testing.T) {
	ctx := context.Background()
	db := testStore(t)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('ups','UPS','ups','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	box := secrets.New("old-master-key")
	auth, _ := box.Encrypt([]byte("auth-secret"))
	privacy, _ := box.Encrypt([]byte("privacy-secret"))
	if _, err := db.DB.Exec(`INSERT INTO device_profiles(id,post_id,kind,address,port,username,created_at,encrypted_auth,encrypted_privacy,interval_seconds,enabled) VALUES('poll','ups','ups','192.0.2.1',161,'mon','2026-01-01T00:00:00Z',?,?,60,1)`, auth, privacy); err != nil {
		t.Fatal(err)
	}
	count, err := devices.RekeyCredentials(ctx, db, "old-master-key", "new-master-key")
	if err != nil || count != 1 {
		t.Fatalf("rekey: %d %v", count, err)
	}
	// The new key can decrypt; the old key cannot.
	var blob []byte
	if err := db.DB.QueryRow(`SELECT encrypted_auth FROM device_profiles WHERE id='poll'`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	oldBox := secrets.New("old-master-key")
	if _, err := oldBox.Decrypt(blob); err == nil {
		t.Fatal("old key still decrypts credentials after rekey")
	}
	newBox := secrets.New("new-master-key")
	decrypted, err := newBox.Decrypt(blob)
	if err != nil || string(decrypted) != "auth-secret" {
		t.Fatalf("new key decryption: %q %v", decrypted, err)
	}
}