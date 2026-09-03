//go:build wasm

package rand

import (
	"syscall/js"
)

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) (err error) {
	if len(b) == 0 {
		return nil
	}

	crypto := js.Global().Get("crypto")
	if crypto.IsNull() || crypto.IsUndefined() {
		return ErrNoCSPRNG
	}

	getRandomValues := crypto.Get("getRandomValues")
	if getRandomValues.Type() != js.TypeFunction {
		return ErrNoCSPRNG
	}

	defer func() {
		if r := recover(); r != nil {
			err = ErrCSPRNGFailed
		}
	}()

	offset := 0
	total := len(b)
	uint8ArrayCls := js.Global().Get("Uint8Array")

	for offset < total {
		chunkSize := total - offset
		if chunkSize > maxChunk {
			chunkSize = maxChunk
		}

		uint8Array := uint8ArrayCls.New(chunkSize)
		crypto.Call("getRandomValues", uint8Array)
		js.CopyBytesToGo(b[offset:offset+chunkSize], uint8Array)

		offset += chunkSize
	}

	return nil
}
