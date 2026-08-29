package secrets

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	box := New("an installation master key")
	if !box.Enabled() {
		t.Fatal("box should be enabled with a key")
	}
	plaintext := []byte("auth-password: secret")
	blob, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	decrypted, err := box.Decrypt(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted value does not match")
	}
	// Nonces are fresh per encryption.
	again, _ := box.Encrypt(plaintext)
	if bytes.Equal(blob, again) {
		t.Fatal("identical ciphertext for identical plaintext")
	}
}

func TestBoxDisabledWithoutKey(t *testing.T) {
	box := New("")
	if box.Enabled() {
		t.Fatal("box without a key must be disabled")
	}
	if _, err := box.Encrypt([]byte("x")); err == nil {
		t.Fatal("encrypt without a key succeeded")
	}
	if _, err := box.Decrypt([]byte("x")); err == nil {
		t.Fatal("decrypt without a key succeeded")
	}
}

func TestDifferentKeysCannotDecrypt(t *testing.T) {
	blob, err := New("key-a").Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("key-b").Decrypt(blob); err == nil {
		t.Fatal("wrong key decrypted a credential")
	}
}
