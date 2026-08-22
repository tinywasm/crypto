package asym_test

import (
	"bytes"
	"testing"

	"github.com/tinywasm/crypto/asym"
)

func TestKeyParsingErrors(t *testing.T) {
	// Test Sign with invalid private key
	_, err := asym.Sign([]byte("message"), []byte("invalid key"))
	if err == nil {
		t.Error("expected error for invalid private key, got nil")
	}

	// Test Verify with invalid public key
	_, err = asym.Verify([]byte("message"), []byte("signature"), []byte("invalid key"))
	if err == nil {
		t.Error("expected error for invalid public key, got nil")
	}

	// Test EncryptAsymmetric with invalid public key
	_, err = asym.EncryptAsymmetric([]byte("plaintext"), []byte("invalid key"))
	if err == nil {
		t.Error("expected error for invalid public key, got nil")
	}

	// Test DecryptAsymmetric with invalid private key
	_, err = asym.DecryptAsymmetric([]byte("ciphertext"), []byte("invalid key"))
	if err == nil {
		t.Error("expected error for invalid private key, got nil")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if len(pub) == 0 {
		t.Error("public key is empty")
	}

	if len(priv) == 0 {
		t.Error("private key is empty")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("this is a test message")
	signature, err := asym.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := asym.Verify(message, signature, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !ok {
		t.Error("signature verification failed")
	}
}

func TestSignVerifyError(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test with wrong key
	wrongPub, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("this is a test message")
	signature, err := asym.Sign(message, priv)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := asym.Verify(message, signature, wrongPub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Error("expected signature verification to fail with wrong key")
	}

	// Test with corrupted signature
	signature[0] ^= 0xff
	ok, err = asym.Verify(message, signature, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Error("expected signature verification to fail with corrupted signature")
	}
}

func TestEncryptDecryptAsymmetric(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte("hello asymmetric world")

	ciphertext, err := asym.EncryptAsymmetric(plaintext, pub)
	if err != nil {
		t.Fatalf("EncryptAsymmetric failed: %v", err)
	}

	decrypted, err := asym.DecryptAsymmetric(ciphertext, priv)
	if err != nil {
		t.Fatalf("DecryptAsymmetric failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptAsymmetricError(t *testing.T) {
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Test with wrong key
	_, wrongPriv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte("hello asymmetric world")
	ciphertext, err := asym.EncryptAsymmetric(plaintext, pub)
	if err != nil {
		t.Fatalf("EncryptAsymmetric failed: %v", err)
	}

	_, err = asym.DecryptAsymmetric(ciphertext, wrongPriv)
	if err == nil {
		t.Error("expected error for wrong private key, got nil")
	}

	// Test with corrupted ciphertext
	ciphertext[0] ^= 0xff
	_, err = asym.DecryptAsymmetric(ciphertext, priv)
	if err == nil {
		t.Error("expected error for corrupted ciphertext, got nil")
	}
}
