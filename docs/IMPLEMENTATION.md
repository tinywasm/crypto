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

## 3. Aleatoriedad / Randomness (`github.com/tinywasm/crypto/rand`)

El paquete `rand` provee la fuente de entropía segura para el ecosistema.

### Guía de Selección / Want -> Use

| Quiero | Uso |
|---|---|
| Un secreto listo para cookie/state/client_secret | `rand.Secret()` |
| Un secreto con largo impuesto por el formato | `rand.SecretN(n)` |
| Bytes crudos para una clave | `rand.Bytes(n)` |
| Llenar un buffer que ya tengo | `rand.Read(b)` |

### Manejo de Errores en WebAssembly (WASM)

En entornos WASM, `rand.Read` valida que `globalThis.crypto` y `getRandomValues` estén disponibles y ejecuta las llamadas en trozos de a lo sumo 65536 bytes (`maxChunk`) para evitar `QuotaExceededError`.

Si el generador no está disponible o rechaza la solicitud, `rand.Read` devuelve `ErrNoCSPRNG` o `ErrCSPRNGFailed`. El consumidor debe propagar y manejar estos errores siempre.

## 4. Dual Testing Implementation

### 4.1 `shared_test.go`
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

### 4.2 `backStlib_test.go`
Native Go tests entry point:
```go
//go:build !wasm

package crypto

import "testing"

func TestCrypto_Native(t *testing.T) {
    RunCryptoTests(t)
}
```

### 4.3 `frontWasm_test.go`
TinyGo execution wrapper (browser-side assertions via `gotest` headless):
```go
//go:build wasm

package crypto

import "testing"

func TestCrypto_WASM(t *testing.T) {
    RunCryptoTests(t)
}
```
