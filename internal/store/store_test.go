package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenMigrateReopenAndRejectFuture(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := s.DB.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != SchemaVersion {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(99,'now')`)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = Open(ctx, dir); err == nil {
		t.Fatal("future schema accepted")
	}
}

func TestOpenRejectsUnusableDataPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("file accepted as directory")
	}
}

func TestStoppedDatabaseBackupRestore(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	s, err := Open(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('host-a','Host A','host','now','now')`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(source, "watchpost.db"))
	if err != nil {
		t.Fatal(err)
	}
	restored := t.TempDir()
	if err = os.WriteFile(filepath.Join(restored, "watchpost.db"), bytes, 0600); err != nil {
		t.Fatal(err)
	}
	copyStore, err := Open(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	var count int
	if err = copyStore.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='host-a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestOpenRejectsCorruptDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "watchpost.db"), []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), dir); err == nil {
		t.Fatal("corrupt database accepted")
	}
}

func TestPhase1DatabaseUpgradesWithoutLosingAgentPairing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('agent-host','Agent Host','host','now','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO agent_connections(installation_id,post_id,hostname,platform,agent_version,created_at) VALUES('agent-install','agent-host','host','linux','0.1.0','now')`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DROP TABLE cluster_outbound_joins`,
		`DROP TABLE cluster_nonces`,
		`DROP TABLE cluster_members`,
		`DROP TABLE cluster_join_requests`,
		`DROP TABLE cluster_invitations`,
		`DROP TABLE cluster_identity`,
		`DELETE FROM schema_migrations WHERE version>=16`,
	} {
		if _, err = s.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var agentCount, version int
	if err = s.DB.QueryRow(`SELECT COUNT(*) FROM agent_connections WHERE installation_id='agent-install' AND post_id='agent-host'`).Scan(&agentCount); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if agentCount != 1 || version != SchemaVersion {
		t.Fatalf("agent pairing or schema lost during upgrade: agents=%d version=%d", agentCount, version)
	}
}
