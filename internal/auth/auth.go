package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/store"
)

const passwordRounds = 210_000
const MinimumPasswordLength = 7

type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}
type Session struct {
	Token, CSRF string
	User        User
}
type Manager struct {
	store    *store.Store
	mu       sync.Mutex
	failures map[string][]time.Time
	// bootstrapTokenRequired gates first-admin setup behind a short-lived
	// bootstrap token when the node is externally reachable or the operator
	// configured one. Loopback-only setup may remain direct.
	bootstrapTokenRequired bool
}

func New(s *store.Store) *Manager { return &Manager{store: s, failures: map[string][]time.Time{}} }

func (m *Manager) SetBootstrapTokenRequired(required bool) { m.bootstrapTokenRequired = required }
func (m *Manager) BootstrapTokenRequired() bool            { return m.bootstrapTokenRequired }

// SetBootstrapToken persists only a hash of the bootstrap token, never the
// raw value. Re-supplying a token resets its consumption so a restart prints a
// fresh token without leaving a stale consumed record behind.
func (m *Manager) SetBootstrapToken(ctx context.Context, raw string, expiresAt time.Time) error {
	if raw == "" {
		return errors.New("bootstrap token required")
	}
	hash := sha256.Sum256([]byte(raw))
	_, err := m.store.DB.ExecContext(ctx, `INSERT INTO bootstrap_tokens(token_hash,expires_at) VALUES(?,?) ON CONFLICT(token_hash) DO UPDATE SET expires_at=excluded.expires_at,consumed_at=NULL`, hash[:], expiresAt.UTC().Format(time.RFC3339Nano))
	return err
}

// GenerateBootstrapToken issues a fresh short-lived token and returns the raw
// value exactly once for console printing.
func (m *Manager) GenerateBootstrapToken(ctx context.Context, lifetime time.Duration) (string, error) {
	raw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if err := m.SetBootstrapToken(ctx, raw, time.Now().UTC().Add(lifetime)); err != nil {
		return "", err
	}
	return raw, nil
}

func (m *Manager) Setup(ctx context.Context, email, password, token string) (User, error) {
	if !strings.Contains(email, "@") || len(password) < MinimumPasswordLength {
		return User{}, fmt.Errorf("valid email and password of at least %d characters required", MinimumPasswordLength)
	}
	hash, err := passwordHash(password)
	if err != nil {
		return User{}, err
	}
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return User{}, err
	}
	if count != 0 {
		return User{}, errors.New("setup already completed")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Bootstrap-token consumption and first-admin creation are one atomic
	// transaction: replaying a consumed token or racing a concurrent second
	// setup both fail closed.
	if m.bootstrapTokenRequired {
		tokenHash := sha256.Sum256([]byte(token))
		result, err := tx.ExecContext(ctx, `UPDATE bootstrap_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?`, now, tokenHash[:], now)
		if err != nil {
			return User{}, err
		}
		consumed, _ := result.RowsAffected()
		if consumed != 1 {
			return User{}, errors.New("bootstrap token required or invalid")
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,'admin',?)`, strings.TrimSpace(email), hash, now)
	if err != nil {
		return User{}, err
	}
	id, _ := result.LastInsertId()
	if err = audit.Insert(ctx, tx, audit.Entry{ActorID: id, Action: "setup", ObjectType: "user", ObjectID: fmt.Sprint(id), Detail: "first administrator created"}); err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: id, Email: email, Role: "admin"}, nil
}

func (m *Manager) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := m.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func validRole(role string) bool { return role == "admin" || role == "operator" || role == "viewer" }

func (m *Manager) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := m.store.DB.QueryContext(ctx, `SELECT id,email,role FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []User{}
	for rows.Next() {
		var u User
		if err = rows.Scan(&u.ID, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		items = append(items, u)
	}
	return items, rows.Err()
}

func (m *Manager) CreateUser(ctx context.Context, email, password, role string, entry audit.Entry) (User, error) {
	if !strings.Contains(email, "@") || len(password) < MinimumPasswordLength || !validRole(role) {
		return User{}, errors.New("valid email, password of at least 7 characters, and role required")
	}
	hash, err := passwordHash(password)
	if err != nil {
		return User{}, err
	}
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)`, strings.TrimSpace(email), hash, role, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return User{}, err
	}
	id, _ := result.LastInsertId()
	entry.ObjectType = "user"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return User{}, err
	}
	if err = tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: id, Email: strings.TrimSpace(email), Role: role}, nil
}

func (m *Manager) SetRole(ctx context.Context, id int64, role string, entry audit.Entry) error {
	if !validRole(role) {
		return errors.New("invalid role")
	}
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, role, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	entry.ObjectType = "user"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetPassword rotates a user's password, revoking every session for that
// user, and records the change atomically. Reset-without-revocation is not the
// default; a separate explicit operation would be needed for that.
func (m *Manager) ResetPassword(ctx context.Context, id int64, newPassword string, entry audit.Entry) error {
	if len(newPassword) < MinimumPasswordLength {
		return errors.New("password must be at least 7 characters")
	}
	hash, err := passwordHash(newPassword)
	if err != nil {
		return err
	}
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	// A password reset always revokes the user's active sessions so a stolen
	// session cannot outlive the supposed reset.
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return err
	}
	entry.ObjectType = "user"
	entry.ObjectID = fmt.Sprint(id)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) RevokeSessions(ctx context.Context, userID int64, entry audit.Entry) (int64, error) {
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	if err != nil {
		return 0, err
	}
	entry.ObjectType = "user"
	entry.ObjectID = fmt.Sprint(userID)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ChangePassword verifies the current password and rotates it, revoking every
// other session for the user while keeping the session identified by
// keepToken.
func (m *Manager) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword, keepToken string, entry audit.Entry) error {
	if len(newPassword) < MinimumPasswordLength {
		return errors.New("password must be at least 7 characters")
	}
	var hash []byte
	if err := m.store.DB.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil {
		return err
	}
	if !verifyPassword(currentPassword, hash) {
		return errors.New("current password incorrect")
	}
	next, err := passwordHash(newPassword)
	if err != nil {
		return err
	}
	keep := tokenHash(keepToken)
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND token_hash<>?`, userID, keep); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, next, userID); err != nil {
		return err
	}
	entry.ActorID = userID
	entry.ObjectType = "user"
	entry.ObjectID = fmt.Sprint(userID)
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) Login(ctx context.Context, email, password string, entry audit.Entry) (Session, error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if !m.allow(key) {
		return Session{}, errors.New("login temporarily throttled")
	}
	var u User
	var hash []byte
	err := m.store.DB.QueryRowContext(ctx, `SELECT id,email,role,password_hash FROM users WHERE email=? COLLATE NOCASE`, strings.TrimSpace(email)).Scan(&u.ID, &u.Email, &u.Role, &hash)
	if err != nil || !verifyPassword(password, hash) {
		m.failed(key)
		return Session{}, errors.New("invalid credentials")
	}
	m.clear(key)
	token, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return Session{}, err
	}
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)`, tokenHash(token), u.ID, csrf, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		return Session{}, err
	}
	entry.ActorID = u.ID
	entry.ObjectType = "session"
	entry.ObjectID = ""
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return Session{Token: token, CSRF: csrf, User: u}, nil
}

func (m *Manager) Authenticate(ctx context.Context, token string) (Session, error) {
	var s Session
	var expires string
	err := m.store.DB.QueryRowContext(ctx, `SELECT u.id,u.email,u.role,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, tokenHash(token)).Scan(&s.User.ID, &s.User.Email, &s.User.Role, &s.CSRF, &expires)
	if err != nil {
		return Session{}, sql.ErrNoRows
	}
	t, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || time.Now().After(t) {
		return Session{}, sql.ErrNoRows
	}
	return s, nil
}
func (m *Manager) Logout(ctx context.Context, token string, entry audit.Entry) error {
	tx, err := m.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(token)); err != nil {
		return err
	}
	entry.ObjectType = "session"
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

func passwordHash(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	derived := derive([]byte(password), salt, passwordRounds)
	return append(salt, derived...), nil
}
func verifyPassword(password string, encoded []byte) bool {
	if len(encoded) != 48 {
		return false
	}
	return hmac.Equal(encoded[16:], derive([]byte(password), encoded[:16], passwordRounds))
}
func derive(password, salt []byte, rounds int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	block[len(salt)+3] = 1
	mac := hmac.New(sha256.New, password)
	mac.Write(block)
	u := mac.Sum(nil)
	out := append([]byte{}, u...)
	for i := 1; i < rounds; i++ {
		mac = hmac.New(sha256.New, password)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func tokenHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }
func (m *Manager) allow(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	kept := m.failures[key][:0]
	for _, at := range m.failures[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	m.failures[key] = kept
	return len(kept) < 5
}
func (m *Manager) failed(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures[key] = append(m.failures[key], time.Now())
}
func (m *Manager) clear(key string) { m.mu.Lock(); defer m.mu.Unlock(); delete(m.failures, key) }
