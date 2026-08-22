# Architecture: TinyWASM Crypto Layer

The `crypto` module is an isomorphic library designed to provide cryptographic capabilities directly to both the backend (Standard Go) and the frontend (WebAssembly via TinyGo).

## 1. Design Philosophy

### 1.1 Direct Package API
The library uses a stateless, direct API approach. Instead of requiring
developers to instantiate a struct `crypto.New()`, each leaf subpackage
exposes plain package-level functions (`aesgcm.Encrypt`, `asym.Sign`,
`hmac.HMACSHA256`, etc.). This reduces verbosity and keeps imports granular.
The root package only exposes `Random` (entropy).

Because the leaf packages handle random entropy generation and pure math
evaluation (AES, ECDSA, ECDH, HMAC), no persistent configuration object (struct
instance) is necessary to execute these operations.

### 1.2 Isomorphism and Standards
Both the native backend runtime and the TinyGo WebAssembly runtime implement identical cryptographic algorithms over standard signatures. There is 100% behavioral equivalence.
- The standard library's `crypto` subpackages are used internally, except tailored implementations for entropy collection depending on the environment (e.g., `crypto/rand`'s `Read` mapping to the stdlib `crypto/rand` natively, and to `crypto.getRandomValues()` internally on the WebAssembly browser side).
- **Encodings are not included:** To keep the binary size minimal, encodings like Base64 or Hex are not part of this package. They are provided as zero-dependency packages in the ecosystem (e.g., `github.com/tinywasm/base64`).

### 1.3 Leaf Subpackages — the only import path
The previous root package (`tinycrypto.go` + `hmac.go`) was deliberately heavy:
it concentrated `crypto/aes`, `crypto/x509`, `crypto/ecdsa`, `crypto/elliptic`,
`crypto/ecdh` so consumers never imported them directly. That bloat is now
removed: **the root package only exposes `Random`** and must not be used for
crypto. Every capability lives in its own leaf:

```
crypto/subtle/     — constant-time comparison
crypto/blowfish/   — block cipher (bcrypt's building block)
crypto/bcrypt/     — password hashing
crypto/rand/       — entropy, the single entropy source for the whole library
crypto/hmac/       — HMACSHA256, HMACEqual              (crypto/hmac, sha256)
crypto/aesgcm/     — Encrypt, Decrypt                   (crypto/aes, cipher)
crypto/asym/       — GenerateKeyPair, Sign, Verify,
                     EncryptAsymmetric, DecryptAsymmetric (ecdsa, ecdh, x509)
```

Each leaf subpackage is verified to carry zero disallowed stdlib imports with
`GOOS=js GOARCH=wasm go list -deps ./<pkg>/`, and its binary-size claim is
backed by an actual `tinygo build -target=wasm -no-debug -opt=z` measurement
of a minimal program — see the Binary Size Benchmarks table in `README.md`.

### 1.4 Target Layout — one leaf per capability

§1.3 established leaves for primitives the standard library never shipped. The
same reasoning applies to the primitives the root package already holds, and
measurement showed the cost is not theoretical:

| Minimal program (TinyGo 0.41.1, `-target=wasm -no-debug -opt=z`) | Binary |
|---|---|
| empty `main` (toolchain floor) | 21,731 bytes |
| `crypto/hmac` + `crypto/sha256` called directly | 155,534 bytes |
| the same HMAC through `crypto.HMACSHA256` (root package) | 264,638 bytes |

Importing the root package to compute one HMAC links `crypto/x509`, and x509
drags in `net`, `encoding/pem`, `encoding/asn1`, `math/big`, `fmt` and
`reflect`: **~109 KB that a JWT signer never calls.** Go links a package as a
unit, so the cost is incurred by importing the root at all — no amount of dead
code elimination removes it, because the package's own initialization is a
live root.

The target layout gives every capability its own leaf, so a consumer links
exactly what it calls:

```
crypto/            — Random only (entropy re-export); no crypto (breaking change)
crypto/hmac/       — HMACSHA256, HMACEqual         (crypto/hmac, crypto/sha256)
crypto/aesgcm/     — Encrypt, Decrypt              (crypto/aes, crypto/cipher)
crypto/asym/       — GenerateKeyPair, Sign, Verify,
                     EncryptAsymmetric, DecryptAsymmetric
                                                   (crypto/ecdsa, ecdh, x509)
crypto/bcrypt/     — password hashing
crypto/blowfish/   — block cipher
crypto/subtle/     — constant-time comparison
crypto/rand/       — the single entropy source
```

**Breaking change:** the root no longer re-exports `HMACSHA256`, `Encrypt`,
`Sign`, etc. Consumers must import the leaf they use. The previous shim
cost ~264 KB for a single HMAC because it linked `crypto/x509`; that cost is
now gone for leaf consumers.

**Grouping rule:** packages are grouped by what a consumer imports *together*,
never by "it is all cryptography". `asym` may keep `x509` because anyone
serializing a key pair already accepts that dependency; nobody else should.

## 2. Testing Constraints (Dual Testing Pattern)
To ensure the logic is fully compatible with both executing environments, tests must follow the **WASM/Stlib Dual Testing Pattern**:
1. Business logic of tests is abstracted into a shared runner (`RunCryptoTests`).
2. Two separate test entry files are maintained using appropriate build tags (`//go:build wasm` vs `//go:build !wasm`).
3. Each test entry point delegates execution to the single source of truth in the shared runner.
