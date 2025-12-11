package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"

	. "github.com/tinywasm/fmt"
)

// TinyCrypto is the engine for cryptographic operations.
type TinyCrypto struct{}

// New creates a new TinyCrypto engine.
func New() *TinyCrypto {
	return &TinyCrypto{}
}

// Encrypt performs symmetric encryption of plaintext using AES-GCM with a 32-byte key.
// It returns the ciphertext, which includes the nonce and the encrypted data.
func (c *TinyCrypto) Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, Err("key length must be 32 bytes for AES-256")
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
	if err := readRandom(nonce); err != nil {
		return nil, err
	}

	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt performs symmetric decryption of ciphertext using AES-GCM with a 32-byte key.
func (c *TinyCrypto) Decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	if len(key) != 32 {
		return nil, Err("key length must be 32 bytes for AES-256")
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
		return nil, Err("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateKeyPair generates a new ECDSA key pair for asymmetric cryptography using the P-256 curve.
func (c *TinyCrypto) GenerateKeyPair() (publicKey []byte, privateKey []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, privBytes, nil
}

// EncryptAsymmetric encrypts plaintext for a given public key using ECIES (ECDH + AES-GCM).
// The returned ciphertext includes the ephemeral public key needed for decryption.
func (c *TinyCrypto) EncryptAsymmetric(plaintext, publicKey []byte) (ciphertext []byte, err error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, Err("failed to parse public key:", err)
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, Err("not an ECDSA public key")
	}

	ecdhPub, err := ecdsaPubKey.ECDH()
	if err != nil {
		return nil, Err("failed to convert to ECDH public key:", err)
	}

	// Generate ephemeral key pair
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Derive shared secret
	sharedSecret, err := ephemeral.ECDH(ecdhPub)
	if err != nil {
		return nil, err
	}

	// Use SHA-256 as KDF to get encryption key
	key := sha256.Sum256(sharedSecret)

	// Encrypt with AES-GCM
	encrypted, err := c.Encrypt(plaintext, key[:])
	if err != nil {
		return nil, err
	}

	// Prepend ephemeral public key to ciphertext
	ciphertext = append(ephemeral.PublicKey().Bytes(), encrypted...)

	return ciphertext, nil
}

// DecryptAsymmetric decrypts ciphertext with a private key.
func (c *TinyCrypto) DecryptAsymmetric(ciphertext, privateKey []byte) (plaintext []byte, err error) {
	priv, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, Err("failed to parse private key:", err)
	}

	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, Err("failed to convert to ECDH private key:", err)
	}

	// Extract ephemeral public key
	ephemeralPubBytes := ciphertext[:65]
	ciphertext = ciphertext[65:]

	ephemeralPub, err := ecdh.P256().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, Err("failed to parse ephemeral public key:", err)
	}

	// Derive shared secret
	sharedSecret, err := ecdhPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}

	// Use SHA-256 as KDF to get encryption key
	key := sha256.Sum256(sharedSecret)

	// Decrypt with AES-GCM
	plaintext, err = c.Decrypt(ciphertext, key[:])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sign creates a digital signature for a message using a private key (ECDSA with P-256 and SHA-256).
func (c *TinyCrypto) Sign(message, privateKey []byte) (signature []byte, err error) {
	privKey, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(message)
	signature, err = ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify checks a digital signature of a message using a public key.
func (c *TinyCrypto) Verify(message, signature, publicKey []byte) (ok bool, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false, Err("not an ECDSA public key")
	}

	hash := sha256.Sum256(message)
	ok = ecdsa.VerifyASN1(ecdsaPubKey, hash[:], signature)
	return ok, nil
}
