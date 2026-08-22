package crypto

import "github.com/tinywasm/crypto/rand"

// Random fills b with cryptographically secure random bytes.
func Random(b []byte) error {
	return rand.Read(b)
}
