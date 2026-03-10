# Implementation: TinyWASM Crypto Layer

## 1. Development Rules

> **Note on Standard Rules**: The following rules must be strictly adhered to while modifying the code base.

- **Single Responsibility Principle (SRP):** Every file must have a single, well-defined purpose.
- **Frontend Go Compatibility:** Maximum compatibility with TinyGo is required. The standard library should not be used when it conflicts with tinywasm implementations; for example, use `tinywasm/fmt` instead of `fmt`, `strings`, `strconv`, `errors`; also use `tinywasm/time` and `tinywasm/json`.
- **WASM/Stlib Dual Testing Pattern (Backend vs Frontend):**
    - **Separate Implementation:** Use build tags to separate logic.
        - `frontWasm_test.go` -> `//go:build wasm`
        - `backStlib_test.go` -> `//go:build !wasm`
    - **Shared Runner:** Both files MUST call a shared test runner (e.g., `RunCryptoTests(t)`) to avoid code duplication.
- **Testing:** For Go tests, always use `gotest` (`github.com/tinywasm/devflow/cmd/gotest`). It evaluates standard tests and detects/runs WASM tests simultaneously.
- **Documentation First:** Document architectural changes and implementations thoroughly in `docs/` and link them in the index `README.md`.

## 2. API Contract Shift

**Before:**
```go
engine := crypto.New()
ciphertext, err := engine.Encrypt(plaintext, key)
```

**After:**
```go
ciphertext, err := crypto.Encrypt(plaintext, key)
```
Struct `TinyCrypto` and its constructor `New()` are to be completely removed. All previously attached methods become package-global functions. Internal state is zero, ensuring functions are pure and thread-safe.

## 3. Dual Testing Implementation

### 3.1 `shared_test.go`
Contains the shared internal validation, abstracting standard library assumptions:
```go
package crypto

import "testing"

func RunCryptoTests(t *testing.T) {
   t.Run("EncryptDecrypt", testEncryptDecrypt)
   t.Run("SignVerify", testSignVerify)
   // ...
}

func testEncryptDecrypt(t *testing.T) { /* ... implementation ... */ }
```

### 3.2 `backStlib_test.go`
Native Go tests entry point:
```go
//go:build !wasm

package crypto

import "testing"

func TestCrypto_Native(t *testing.T) {
    RunCryptoTests(t)
}
```

### 3.3 `frontWasm_test.go`
TinyGo execution wrapper (browser-side assertions via `gotest` headless):
```go
//go:build wasm

package crypto

import "testing"

func TestCrypto_WASM(t *testing.T) {
    RunCryptoTests(t)
}
```
