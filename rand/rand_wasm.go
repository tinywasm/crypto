//go:build wasm

package rand

import (
	"syscall/js"
)

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) error {
	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.Global().Get("crypto").Call("getRandomValues", uint8Array)
	js.CopyBytesToGo(b, uint8Array)
	return nil
}
