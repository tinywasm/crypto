package aesgcm_test

import (
	"bytes"
	"testing"

	"github.com/tinywasm/crypto/aesgcm"
	"github.com/tinywasm/crypto/rand"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("hello world")

	ciphertext, err := aesgcm.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := aesgcm.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptError(t *testing.T) {
	// Test with wrong key size
	key := make([]byte, 16)
	plaintext := []byte("hello world")
	_, err := aesgcm.Encrypt(plaintext, key)
	if err == nil {
		t.Error("expected error for wrong key size, got nil")
	}

	// Test with corrupted ciphertext
	realKey := make([]byte, 32)
	if err := rand.Read(realKey); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	ciphertext, _ := aesgcm.Encrypt(plaintext, realKey)
	ciphertext[0] ^= 0xff // corrupt the nonce
	_, err = aesgcm.Decrypt(ciphertext, realKey)
	if err == nil {
		t.Error("expected error for corrupted ciphertext, got nil")
	}
}
