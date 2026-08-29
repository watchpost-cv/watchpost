// Package secrets encrypts credentials at rest with an installation master key
// supplied outside the database. The key is derived from the master secret via
// SHA-256; each value is encrypted with AES-256-GCM and a fresh random nonce.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Box encrypts and decrypts credential material with the installation master
// key. A zero-value Box (no master key configured) is disabled.
type Box struct {
	key [32]byte
	on  bool
}

func New(masterKey string) *Box {
	box := &Box{}
	if masterKey != "" {
		box.key = sha256.Sum256([]byte(masterKey))
		box.on = true
	}
	return box
}

func (b *Box) Enabled() bool { return b != nil && b.on }

func (b *Box) Encrypt(plaintext []byte) ([]byte, error) {
	if !b.Enabled() {
		return nil, errors.New("no master key configured; credentials cannot be stored at rest")
	}
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (b *Box) Decrypt(blob []byte) ([]byte, error) {
	if !b.Enabled() {
		return nil, errors.New("no master key configured; stored credentials cannot be read")
	}
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("encrypted credential malformed")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}