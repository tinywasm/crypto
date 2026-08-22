package asym

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"

	. "github.com/tinywasm/fmt"
	"github.com/tinywasm/crypto/aesgcm"
	"github.com/tinywasm/crypto/rand"
)

const (
	ErrParsePublicKey       = "failed to parse public key:"
	ErrNotECDSAPublicKey    = "not an ECDSA public key"
	ErrConvertECDHPublicKey = "failed to convert to ECDH public key:"
	ErrParsePrivateKey      = "failed to parse private key:"
	ErrConvertECDHPrivate   = "failed to convert to ECDH private key:"
	ErrParseEphemeralPubKey = "failed to parse ephemeral public key:"
)

// randReader adapts the environment-agnostic crypto/rand leaf package to the
// io.Reader that ecdsa and ecdh require. It exists so this package has a
// SINGLE entropy source: every random byte in the library — nonces, keys,
// signatures, bcrypt salts — comes from crypto/rand.Read, which resolves to
// crypto.getRandomValues in the browser and the stdlib CSPRNG natively.
type randReader struct{}

func (randReader) Read(b []byte) (int, error) {
	if err := rand.Read(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// GenerateKeyPair generates a new ECDSA key pair for asymmetric cryptography using the P-256 curve.
func GenerateKeyPair() (publicKey []byte, privateKey []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), randReader{})
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
func EncryptAsymmetric(plaintext, publicKey []byte) (ciphertext []byte, err error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, Err(ErrParsePublicKey, err)
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, Err(ErrNotECDSAPublicKey)
	}

	ecdhPub, err := ecdsaPubKey.ECDH()
	if err != nil {
		return nil, Err(ErrConvertECDHPublicKey, err)
	}

	// Generate ephemeral key pair
	ephemeral, err := ecdh.P256().GenerateKey(randReader{})
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
	encrypted, err := aesgcm.Encrypt(plaintext, key[:])
	if err != nil {
		return nil, err
	}

	// Prepend ephemeral public key to ciphertext
	ciphertext = append(ephemeral.PublicKey().Bytes(), encrypted...)

	return ciphertext, nil
}

// DecryptAsymmetric decrypts ciphertext with a private key.
func DecryptAsymmetric(ciphertext, privateKey []byte) (plaintext []byte, err error) {
	priv, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, Err(ErrParsePrivateKey, err)
	}

	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, Err(ErrConvertECDHPrivate, err)
	}

	// Extract ephemeral public key
	ephemeralPubBytes := ciphertext[:65]
	ciphertext = ciphertext[65:]

	ephemeralPub, err := ecdh.P256().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, Err(ErrParseEphemeralPubKey, err)
	}

	// Derive shared secret
	sharedSecret, err := ecdhPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}

	// Use SHA-256 as KDF to get encryption key
	key := sha256.Sum256(sharedSecret)

	// Decrypt with AES-GCM
	plaintext, err = aesgcm.Decrypt(ciphertext, key[:])
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Sign creates a digital signature for a message using a private key (ECDSA with P-256 and SHA-256).
func Sign(message, privateKey []byte) (signature []byte, err error) {
	privKey, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(message)
	signature, err = ecdsa.SignASN1(randReader{}, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify checks a digital signature of a message using a public key.
func Verify(message, signature, publicKey []byte) (ok bool, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false, Err(ErrNotECDSAPublicKey)
	}

	hash := sha256.Sum256(message)
	ok = ecdsa.VerifyASN1(ecdsaPubKey, hash[:], signature)
	return ok, nil
}
