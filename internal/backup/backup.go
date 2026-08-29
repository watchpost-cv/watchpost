// Package backup provides online (live-node) SQLite backups via VACUUM INTO,
// optional passphrase encryption with AES-256-GCM, and verified restore. A
// backup never contains the passphrase or master key that protects it.
//
// Encrypted backups use a versioned container whose header carries the KDF
// identifier, a fresh random salt, the work factor, the nonce and the version;
// the header is authenticated as GCM additional data so it cannot be modified
// undetected. The archive is written to a private temporary file, flushed, and
// atomically renamed into place.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/store"
)

// encryptedMagicV1 and encryptedMagicV2 are versioned container headers. They
// are not secrets.
var encryptedMagicV1 = []byte("WPBK\x01")
var encryptedMagicV2 = []byte("WPBK\x02")

// kdfPBKDF2SHA256 identifies PBKDF2-HMAC-SHA256 in the version-2 header.
const kdfPBKDF2SHA256 = 1

// MinimumPassphraseLength is the floor for operator-supplied backup
// passphrases.
const MinimumPassphraseLength = 10

// DefaultWorkFactor is the PBKDF2 iteration count used for new backups.
const DefaultWorkFactor = 210000

// saltPrefix is the fixed salt used by version-1 archives. Version 2 uses a
// fresh random salt per backup; version 1 remains readable for compatibility.
var saltPrefix = []byte("watchpost-backup")

// Create writes a consistent online snapshot of the database to outputPath.
// When passphrase is non-empty it must be at least MinimumPassphraseLength
// characters; the backup is then written as a version-2 encrypted container.
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
	if err := os.Remove(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	defer os.Remove(temporary)
	// VACUUM INTO produces a consistent snapshot without stopping the node.
	if _, err := db.DB.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(temporary, "'", "''")+`'`); err != nil {
		return fmt.Errorf("online snapshot: %w", err)
	}
	if passphrase == "" {
		return atomicWrite(temporary, outputPath)
	}
	plaintext, err := os.ReadFile(temporary)
	if err != nil {
		return err
	}
	container, err := encryptV2(passphrase, plaintext)
	if err != nil {
		return err
	}
	if err := os.WriteFile(temporary, container, 0600); err != nil {
		return err
	}
	return atomicWrite(temporary, outputPath)
}

// encryptV2 builds a version-2 container: header (version, KDF, work factor,
// random salt, nonce) authenticated as GCM additional data, followed by the
// ciphertext.
func encryptV2(passphrase string, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key[hash.Hash](sha256.New, passphrase, salt, DefaultWorkFactor, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := buildHeader(salt, nonce)
	container := append([]byte{}, header...)
	container = gcm.Seal(container, nonce, plaintext, header)
	return container, nil
}

func buildHeader(salt, nonce []byte) []byte {
	header := append([]byte{}, encryptedMagicV2...)
	header = append(header, kdfPBKDF2SHA256)
	work := [4]byte{}
	binary.BigEndian.PutUint32(work[:], uint32(DefaultWorkFactor))
	header = append(header, work[:]...)
	header = append(header, byte(len(salt)))
	header = append(header, salt...)
	header = append(header, byte(len(nonce)))
	header = append(header, nonce...)
	return header
}

// atomicWrite flushes the source to the destination via a rename so an
// interrupted write never leaves a partial final backup.
func atomicWrite(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".watchpost-backup-final-*")
	if err != nil {
		return err
	}
	name := output.Name()
	defer os.Remove(name)
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
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
		plaintext, err := decrypt(passphrase, blob)
		if err != nil {
			return err
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
	if err = temporary.Sync(); err == nil {
		err = temporary.Close()
	} else {
		temporary.Close()
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func isEncrypted(blob []byte) bool {
	if len(blob) < 5 {
		return false
	}
	return string(blob[:4]) == "WPBK"
}

func decrypt(passphrase string, blob []byte) ([]byte, error) {
	if len(blob) < 5 {
		return nil, errors.New("backup container malformed")
	}
	switch blob[4] {
	case 1:
		return decryptV1(passphrase, blob)
	case 2:
		return decryptV2(passphrase, blob)
	}
	return nil, errors.New("unsupported backup version")
}

// decryptV1 reads legacy archives (fixed salt, header not authenticated beyond
// the magic). It remains readable for compatibility; new backups are v2.
func decryptV1(passphrase string, blob []byte) ([]byte, error) {
	if len(blob) < len(encryptedMagicV1)+4+12 {
		return nil, errors.New("backup container malformed")
	}
	key, err := pbkdf2.Key[hash.Hash](sha256.New, passphrase, saltPrefix, DefaultWorkFactor, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := blob[len(encryptedMagicV1)+4 : len(encryptedMagicV1)+4+gcm.NonceSize()]
	ciphertext := blob[len(encryptedMagicV1)+4+gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, encryptedMagicV1)
	if err != nil {
		return nil, errors.New("backup decryption failed: wrong passphrase or corrupt archive")
	}
	return plaintext, nil
}

func decryptV2(passphrase string, blob []byte) ([]byte, error) {
	if len(blob) < 4+1+1+4+1+1+1+12 {
		return nil, errors.New("backup container malformed")
	}
	offset := 4 + 1 // magic + version
	kdf := blob[offset]
	offset++
	if kdf != kdfPBKDF2SHA256 {
		return nil, errors.New("unsupported backup KDF")
	}
	workFactor := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	if workFactor < 1 || workFactor > 100000000 {
		return nil, errors.New("backup work factor out of bounds")
	}
	saltLength := int(blob[offset])
	offset++
	if saltLength < 8 || saltLength > 64 || len(blob) < offset+saltLength {
		return nil, errors.New("backup salt out of bounds")
	}
	salt := blob[offset : offset+saltLength]
	offset += saltLength
	nonceLength := int(blob[offset])
	offset++
	if nonceLength < 8 || nonceLength > 24 || len(blob) < offset+nonceLength {
		return nil, errors.New("backup nonce out of bounds")
	}
	nonce := blob[offset : offset+nonceLength]
	header := blob[:offset+nonceLength]
	ciphertext := blob[offset+nonceLength:]
	key, err := pbkdf2.Key[hash.Hash](sha256.New, passphrase, salt, workFactor, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, errors.New("backup decryption failed: wrong passphrase, tampered metadata, or corrupt archive")
	}
	return plaintext, nil
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