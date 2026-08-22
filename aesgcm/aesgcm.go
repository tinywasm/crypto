package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"

	. "github.com/tinywasm/fmt"
	"github.com/tinywasm/crypto/rand"
)

const (
	ErrKeySize         = "key length must be 32 bytes for AES-256"
	ErrCiphertextShort = "ciphertext too short"
)

// Encrypt performs symmetric encryption of plaintext using AES-GCM with a 32-byte key.
// It returns the ciphertext, which includes the nonce and the encrypted data.
func Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, Err(ErrKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt performs symmetric decryption of ciphertext using AES-GCM with a 32-byte key.
func Decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	if len(key) != 32 {
		return nil, Err(ErrKeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, Err(ErrCiphertextShort)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
