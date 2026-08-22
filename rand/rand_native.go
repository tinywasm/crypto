//go:build !wasm

package rand

import "crypto/rand"

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) error {
	_, err := rand.Read(b)
	return err
}
