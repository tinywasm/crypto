//go:build !wasm

package crypto

import "crypto/rand"

func readRandom(b []byte) (err error) {
	_, err = rand.Read(b)
	return
}
