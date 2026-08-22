//go:build wasm

package crypto

import (
	"syscall/js"
)

// Random fills b with cryptographically secure random bytes.
func Random(b []byte) (err error) {
	return readRandom(b)
}

func readRandom(b []byte) (err error) {
	// In a browser environment, we can use crypto.getRandomValues.
	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.Global().Get("crypto").Call("getRandomValues", uint8Array)
	js.CopyBytesToGo(b, uint8Array)
	return nil
}
