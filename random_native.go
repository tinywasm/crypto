//go:build !wasm

package crypto

import "crypto/rand"

// Random fills b with cryptographically secure random bytes.
func Random(b []byte) (err error) {
	return readRandom(b)
}

func readRandom(b []byte) (err error) {
	_, err = rand.Read(b)
	return
}
