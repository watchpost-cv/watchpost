package devices

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/secrets"
	"github.com/watchpost-cv/watchpost/internal/store"
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

func TestProfileCredentialsEncryptedRoundTrip(t *testing.T) {
	db := testStore(t)
	box := secrets.New("installation-master-key")
	store := NewProfileStoreWithKey(db, box)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('ups-1','UPS','ups','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	profile := SavedProfile{ID: "ups-poll", PostID: "ups-1", Kind: "ups", Address: "192.0.2.10", Port: 161, Username: "monitor", OIDs: []OID{{Name: "battery_charge", OID: ".1.3.6.1.2.1.33.1.2.4.0", Unit: "percent"}}, AuthPassword: "auth-secret", PrivacyPassword: "privacy-secret", IntervalSeconds: 60}
	if err := store.Save(context.Background(), profile, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	// Credentials are never returned in listing.
	items, err := store.List(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %#v %v", items, err)
	}
	if items[0].AuthPassword != "" || items[0].PrivacyPassword != "" {
		t.Fatal("stored profile returned credentials")
	}
	// They decrypt for polling.
	_, config, err := store.Credentials(context.Background(), "ups-poll")
	if err != nil {
		t.Fatal(err)
	}
	if config.AuthPassword != "auth-secret" || config.PrivacyPassword != "privacy-secret" {
		t.Fatalf("credentials did not decrypt correctly: %#v", config)
	}
	// The profile is due and reschedules.
	due, err := store.Due(context.Background(), time.Now().UTC(), 16)
	if err != nil || len(due) != 1 {
		t.Fatalf("due: %#v %v", due, err)
	}
	if err := store.Advance(context.Background(), "ups-poll", 60, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	due, err = store.Due(context.Background(), time.Now().UTC(), 16)
	if err != nil || len(due) != 0 {
		t.Fatalf("profile not rescheduled: %#v %v", due, err)
	}
}

func TestProfileSaveRefusesCredentialsWithoutMasterKey(t *testing.T) {
	db := testStore(t)
	store := NewProfileStore(db)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('ups-1','UPS','ups','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	profile := SavedProfile{ID: "ups-poll", PostID: "ups-1", Kind: "ups", Address: "192.0.2.10", Port: 161, Username: "monitor", OIDs: []OID{{Name: "battery_charge", OID: ".1.3.6.1.2.1.33.1.2.4.0", Unit: "percent"}}, AuthPassword: "auth", PrivacyPassword: "privacy", IntervalSeconds: 60}
	if err := store.Save(context.Background(), profile, audit.Entry{Action: "test"}); err == nil {
		t.Fatal("credential storage succeeded without a master key")
	}
	// Metadata-only profiles still work without a key.
	metadataOnly := profile
	metadataOnly.AuthPassword = ""
	metadataOnly.PrivacyPassword = ""
	metadataOnly.IntervalSeconds = 0
	if err := store.Save(context.Background(), metadataOnly, audit.Entry{Action: "test"}); err != nil {
		t.Fatalf("metadata-only profile rejected: %v", err)
	}
}

func TestWrongMasterKeyCannotReadCredentials(t *testing.T) {
	db := testStore(t)
	box := secrets.New("key-a")
	store := NewProfileStoreWithKey(db, box)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('ups-1','UPS','ups','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	profile := SavedProfile{ID: "ups-poll", PostID: "ups-1", Kind: "ups", Address: "192.0.2.10", Port: 161, Username: "monitor", OIDs: []OID{}, AuthPassword: "auth", PrivacyPassword: "privacy", IntervalSeconds: 60}
	if err := store.Save(context.Background(), profile, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	wrong := NewProfileStoreWithKey(db, secrets.New("key-b"))
	if _, _, err := wrong.Credentials(context.Background(), "ups-poll"); err == nil {
		t.Fatal("wrong master key decrypted credentials")
	}
}
