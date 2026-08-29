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

const SchemaVersion = 11

type Store struct{ DB *sql.DB }

func Open(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "watchpost.db")+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=journal_size_limit(33554432)&_pragma=wal_autocheckpoint(1000)")
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
		version = 1
	}
	if version == 1 {
		statements := []string{
			`CREATE INDEX observations_post_signal_time ON observations(post_id,signal,observed_at)`,
			`CREATE TABLE rules(id TEXT PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), signal TEXT NOT NULL, operator TEXT NOT NULL CHECK(operator IN ('gt','gte','lt','lte')), threshold REAL NOT NULL, duration_seconds INTEGER NOT NULL DEFAULT 0, recovery_threshold REAL, missing_policy TEXT NOT NULL DEFAULT 'unknown', severity TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1)`,
			`CREATE TABLE alerts(id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES rules(id), post_id TEXT NOT NULL REFERENCES posts(id), state TEXT NOT NULL, severity TEXT NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL, acknowledged_at TEXT, resolved_at TEXT, value REAL)`,
			`CREATE INDEX alerts_active ON alerts(rule_id,post_id,state)`,
			`CREATE TABLE notification_routes(id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('webhook','email')), destination TEXT NOT NULL, secret TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1)`,
			`CREATE TABLE notification_deliveries(id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id), route_id TEXT NOT NULL REFERENCES notification_routes(id), state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, delivered_at TEXT, last_error TEXT NOT NULL DEFAULT '', UNIQUE(alert_id,route_id))`,
			`CREATE TABLE incidents(id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT)`,
			`CREATE TABLE incident_alerts(incident_id INTEGER NOT NULL REFERENCES incidents(id), alert_id INTEGER NOT NULL REFERENCES alerts(id), PRIMARY KEY(incident_id,alert_id))`,
			`CREATE TABLE incident_timeline(id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id), at TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL)`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 2: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		statements := []string{
			`CREATE TABLE logs(id INTEGER PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), source TEXT NOT NULL, observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, fields_json TEXT NOT NULL DEFAULT '{}', truncated INTEGER NOT NULL DEFAULT 0)`,
			`CREATE INDEX logs_post_time ON logs(post_id,observed_at)`,
			`CREATE TABLE changes(id INTEGER PRIMARY KEY, post_id TEXT REFERENCES posts(id), kind TEXT NOT NULL, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, summary TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}')`,
			`CREATE TABLE conversations(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), post_id TEXT REFERENCES posts(id), incident_id INTEGER REFERENCES incidents(id), created_at TEXT NOT NULL)`,
			`CREATE TABLE conversation_messages(id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations(id), at TEXT NOT NULL, role TEXT NOT NULL, body TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '[]')`,
			`CREATE TABLE action_requests(id INTEGER PRIMARY KEY, type TEXT NOT NULL, post_id TEXT REFERENCES posts(id), parameters_json TEXT NOT NULL, state TEXT NOT NULL, requested_by INTEGER NOT NULL REFERENCES users(id), approved_by INTEGER REFERENCES users(id), requested_at TEXT NOT NULL, updated_at TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, result_json TEXT NOT NULL DEFAULT '{}')`,
			`CREATE TABLE peers(id TEXT PRIMARY KEY, secret_hash BLOB NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)`,
			`CREATE TABLE federation_outbox(id INTEGER PRIMARY KEY, peer_id TEXT NOT NULL REFERENCES peers(id), event_id TEXT NOT NULL, kind TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT, UNIQUE(peer_id,event_id))`,
			`CREATE TABLE federation_inbox(peer_id TEXT NOT NULL REFERENCES peers(id), event_id TEXT NOT NULL, received_at TEXT NOT NULL, payload_hash BLOB NOT NULL, PRIMARY KEY(peer_id,event_id))`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 3: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(3,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if _, err = tx.ExecContext(ctx, `CREATE TABLE collector_pairing_tokens(token_hash BLOB PRIMARY KEY, post_id TEXT NOT NULL REFERENCES posts(id), expires_at TEXT NOT NULL, used_at TEXT)`); err != nil {
			return fmt.Errorf("migration 4: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(4,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		statements := []string{
			`ALTER TABLE collector_keys ADD COLUMN last_seen_at TEXT`,
			`ALTER TABLE collector_keys ADD COLUMN last_observed_at TEXT`,
			`ALTER TABLE collector_keys ADD COLUMN last_sent_at TEXT`,
			`ALTER TABLE collector_keys ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE collector_keys ADD COLUMN last_rejected_at TEXT`,
			`ALTER TABLE collector_keys ADD COLUMN rejected_count INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE collector_keys ADD COLUMN partial INTEGER NOT NULL DEFAULT 0`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 5: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(5,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 5
	}
	if version == 5 {
		statements := []string{
			`CREATE TABLE device_profiles(id TEXT PRIMARY KEY,post_id TEXT NOT NULL REFERENCES posts(id),kind TEXT NOT NULL,address TEXT NOT NULL,port INTEGER NOT NULL,username TEXT NOT NULL,created_at TEXT NOT NULL)`,
			`CREATE TABLE device_profile_oids(profile_id TEXT NOT NULL REFERENCES device_profiles(id) ON DELETE CASCADE,position INTEGER NOT NULL,name TEXT NOT NULL,oid TEXT NOT NULL,unit TEXT NOT NULL,PRIMARY KEY(profile_id,position))`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 6: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(6,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 6
	}
	if version == 6 {
		if _, err = tx.ExecContext(ctx, `ALTER TABLE posts ADD COLUMN address TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("migration 7: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(7,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 7
	}
	if version == 7 {
		statements := []string{
			`CREATE TABLE agent_pairing_requests(id TEXT PRIMARY KEY,request_secret_hash BLOB NOT NULL,installation_id TEXT NOT NULL,hostname TEXT NOT NULL,platform TEXT NOT NULL,agent_version TEXT NOT NULL,phrase TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','consumed')),post_id TEXT REFERENCES posts(id) ON DELETE CASCADE,expires_at TEXT NOT NULL,created_at TEXT NOT NULL,approved_at TEXT)`,
			`CREATE INDEX agent_pairing_pending ON agent_pairing_requests(state,expires_at,created_at)`,
			`CREATE TABLE agent_connections(installation_id TEXT PRIMARY KEY,post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,hostname TEXT NOT NULL,platform TEXT NOT NULL,agent_version TEXT NOT NULL,created_at TEXT NOT NULL,last_seen_at TEXT,revoked_at TEXT)`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 8: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(8,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 8
	}
	if version == 8 {
		statements := []string{
			`CREATE TABLE check_schedules(id TEXT PRIMARY KEY,post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,kind TEXT NOT NULL,address TEXT NOT NULL,server_name TEXT NOT NULL DEFAULT '',interval_seconds INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,next_run_at TEXT NOT NULL,created_at TEXT NOT NULL)`,
			`CREATE TABLE check_results(id INTEGER PRIMARY KEY,schedule_id TEXT NOT NULL REFERENCES check_schedules(id) ON DELETE CASCADE,checked_at TEXT NOT NULL,ok INTEGER NOT NULL,latency_ms REAL NOT NULL,status INTEGER NOT NULL DEFAULT 0,expires_at TEXT,failure TEXT NOT NULL DEFAULT '')`,
			`CREATE INDEX check_schedules_due ON check_schedules(enabled,next_run_at)`,
			`CREATE INDEX check_results_schedule_time ON check_results(schedule_id,checked_at)`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 9: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(9,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 9
	}
	if version == 9 {
		statements := []string{
			`ALTER TABLE agent_pairing_requests ADD COLUMN terminal_at TEXT`,
			`CREATE TABLE conversation_evidence(id INTEGER PRIMARY KEY,conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,message_id INTEGER NOT NULL REFERENCES conversation_messages(id) ON DELETE CASCADE,kind TEXT NOT NULL CHECK(kind IN ('log','change','alert','incident')),evidence_id INTEGER NOT NULL,summary TEXT NOT NULL,cited_at TEXT NOT NULL)`,
			`CREATE INDEX conversation_evidence_lookup ON conversation_evidence(kind,evidence_id)`,
			`CREATE INDEX conversation_evidence_message ON conversation_evidence(message_id)`,
			`CREATE INDEX observations_observed_at ON observations(observed_at)`,
			`CREATE INDEX check_results_checked_at ON check_results(checked_at)`,
			`CREATE INDEX logs_observed_at ON logs(observed_at)`,
		}
		for _, statement := range statements {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migration 10: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(10,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 10
	}
	if version == 10 {
		if _, err = tx.ExecContext(ctx, `ALTER TABLE collector_keys ADD COLUMN kind TEXT NOT NULL DEFAULT 'collector'`); err != nil {
			return fmt.Errorf("migration 11: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(11,?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		version = 11
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
