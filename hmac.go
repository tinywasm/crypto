package crypto

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/tinywasm/crypto/subtle"
)

// HMACSHA256 returns the HMAC-SHA256 of message under key.
// Used by tinywasm/user to sign JWT session tokens.
func HMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// HMACEqual reports whether two MACs are equal, in constant time.
// A non-constant-time comparison of a MAC is a timing oracle: never
// compare signatures with == or a byte loop that returns early.
func HMACEqual(mac1, mac2 []byte) bool {
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
