//go:build !wasm

package crypto

import "testing"

func TestCrypto_Native(t *testing.T) {
	RunCryptoTests(t)
}
