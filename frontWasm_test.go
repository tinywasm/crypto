//go:build wasm

package crypto

import "testing"

func TestCrypto_WASM(t *testing.T) {
	RunCryptoTests(t)
}
