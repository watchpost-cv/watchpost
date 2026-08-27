package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 1

type Store struct{ DB *sql.DB }

func Open(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "watchpost.db")+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("database schema %d is newer than supported %d", version, SchemaVersion)
	}
	if version == 0 {
		statements := []string{
			`CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash BLOB NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), created_at TEXT NOT NULL)`,
			`CREATE TABLE sessions(token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL)`,
			`CREATE TABLE audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor_user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL)`,
			`CREATE TABLE posts(id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', labels_json TEXT NOT NULL DEFAULT '{}', maintenance INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			`CREATE TABLE post_dependencies(post_id TEXT NOT NULL REFERENCES posts(id), depends_on_id TEXT NOT NULL REFERENCES posts(id), PRIMARY KEY(post_id,depends_on_id), CHECK(post_id<>depends_on_id))`,
			`CREATE TABLE collector_keys(id TEXT PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), secret_hash BLOB NOT NULL, revoked_at TEXT, last_sequence INTEGER NOT NULL DEFAULT 0)`,
			`CREATE TABLE observations(id INTEGER PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), collector_id TEXT NOT NULL REFERENCES collector_keys(id), observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL, sequence INTEGER NOT NULL, signal TEXT NOT NULL, value REAL, unit TEXT NOT NULL, quality TEXT NOT NULL, labels_json TEXT NOT NULL, UNIQUE(collector_id,sequence,signal))`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 1: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Ready(ctx context.Context) error { return s.DB.PingContext(ctx) }

func IsConstraint(err error) bool {
	return err != nil && (errors.Is(err, sql.ErrNoRows) == false) && contains(err.Error(), "constraint failed")
}
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
