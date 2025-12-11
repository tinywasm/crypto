//go:build wasm

package crypto

import (
	"syscall/js"
)

func readRandom(b []byte) (err error) {
	// In a browser environment, we can use crypto.getRandomValues.
	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.Global().Get("crypto").Call("getRandomValues", uint8Array)
	js.CopyBytesToGo(b, uint8Array)
	return nil
}
