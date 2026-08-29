// Package backup provides online (live-node) SQLite backups via VACUUM INTO,
// optional passphrase encryption with AES-256-GCM, and verified restore. A
// backup never contains the passphrase or master key that protects it.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

// encryptedMagic is a versioned container header for passphrase-protected
// backups. It is not a secret.
var encryptedMagic = []byte("WPBK\x01")

// MinimumPassphraseLength is the floor for operator-supplied backup
// passphrases.
const MinimumPassphraseLength = 10

// Create writes a consistent online snapshot of the database to outputPath.
// When passphrase is non-empty it must be at least MinimumPassphraseLength
// characters; the backup is then encrypted with AES-256-GCM under a key
// derived from the passphrase (PBKDF2-HMAC-SHA256, 210,000 rounds).
func Create(ctx context.Context, db *store.Store, outputPath, passphrase string) error {
	if outputPath == "" {
		return errors.New("backup output path required")
	}
	if passphrase != "" && len(passphrase) < MinimumPassphraseLength {
		return fmt.Errorf("backup passphrase must be at least %d characters", MinimumPassphraseLength)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return err
	}
	temporary := outputPath + ".tmp"
	defer os.Remove(temporary)
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	// VACUUM INTO produces a consistent snapshot without stopping the node.
	if _, err := db.DB.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(temporary, "'", "''")+`'`); err != nil {
		return fmt.Errorf("online snapshot: %w", err)
	}
	if passphrase == "" {
		return os.Rename(temporary, outputPath)
	}
	key, err := pbkdf2.Key[hash.Hash](sha256.New, passphrase, []byte("watchpost-backup"), 210000, 32)
	if err != nil {
		return err
	}
	plaintext, err := os.ReadFile(temporary)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(plaintext)))
	container := append(append(append([]byte{}, encryptedMagic...), header...), nonce...)
	container = gcm.Seal(container, nonce, plaintext, encryptedMagic)
	return os.WriteFile(outputPath, container, 0600)
}

// Restore validates and restores a backup into dataDir. Encrypted backups need
// the passphrase. The node must be stopped; force replaces an existing
// database. Restoring a database newer than the binary is refused.
func Restore(ctx context.Context, dataDir, inputPath, passphrase string, force bool) error {
	if inputPath == "" {
		return errors.New("restore input path required")
	}
	blob, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	if isEncrypted(blob) {
		if len(passphrase) < MinimumPassphraseLength {
			return errors.New("passphrase required (minimum 10 characters)")
		}
		key, err := pbkdf2.Key[hash.Hash](sha256.New, passphrase, []byte("watchpost-backup"), 210000, 32)
		if err != nil {
			return err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		if len(blob) < len(encryptedMagic)+4+gcm.NonceSize() {
			return errors.New("backup container malformed")
		}
		nonce := blob[len(encryptedMagic)+4 : len(encryptedMagic)+4+gcm.NonceSize()]
		ciphertext := blob[len(encryptedMagic)+4+gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, encryptedMagic)
		if err != nil {
			return errors.New("backup decryption failed: wrong passphrase or corrupt archive")
		}
		expected := int(binary.BigEndian.Uint32(blob[len(encryptedMagic) : len(encryptedMagic)+4]))
		if expected != len(plaintext) {
			return errors.New("backup container length mismatch")
		}
		blob = plaintext
	}
	if err := validateSQLite(blob); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	destination := filepath.Join(dataDir, "watchpost.db")
	if _, err := os.Stat(destination); err == nil && !force {
		return errors.New("destination database exists; use --force to replace (node must be stopped)")
	}
	temporary, err := os.CreateTemp(dataDir, ".watchpost-restore-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(blob)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func isEncrypted(blob []byte) bool {
	return len(blob) >= len(encryptedMagic) && string(blob[:len(encryptedMagic)]) == string(encryptedMagic)
}

// validateSQLite checks the SQLite header and that the schema is not newer
// than this binary supports.
func validateSQLite(blob []byte) error {
	if len(blob) < 16 || string(blob[:16]) != "SQLite format 3\x00" {
		return errors.New("restored file is not a SQLite database")
	}
	temp := filepath.Join(os.TempDir(), fmt.Sprintf("watchpost-validate-%d.db", time.Now().UnixNano()))
	if err := os.WriteFile(temp, blob, 0600); err != nil {
		return err
	}
	defer os.Remove(temp)
	dsn := temp + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("restore validation: %w", err)
	}
	if version > store.SchemaVersion {
		return fmt.Errorf("restored database schema %d is newer than supported %d", version, store.SchemaVersion)
	}
	return nil
}