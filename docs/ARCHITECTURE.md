# Architecture: TinyWASM Crypto Layer

The `crypto` module is an isomorphic library designed to provide cryptographic capabilities directly to both the backend (Standard Go) and the frontend (WebAssembly via TinyGo).

## 1. Design Philosophy

### 1.1 Direct Package API
The library uses a stateless, direct API approach. Instead of requiring developers to instantiate a struct `crypto.New()`, it exposes plain package-level functions (`crypto.Encrypt`, `crypto.Sign`, `crypto.HMACSHA256`, etc.). This reduces verbosity, simplifies the code style across the project, and improves ergonomics.

Because `crypto` handles random entropy generation and pure math evaluation (AES, ECDSA, ECDH, HMAC), no persistent configuration object (struct instance) is necessary to execute these operations.

### 1.2 Isomorphism and Standards
Both the native backend runtime and the TinyGo WebAssembly runtime implement identical cryptographic algorithms over standard signatures. There is 100% behavioral equivalence.
- The standard library's `crypto` subpackages are used internally, except tailored implementations for entropy collection depending on the environment (e.g., `crypto/rand`'s `Read` mapping to the stdlib `crypto/rand` natively, and to `crypto.getRandomValues()` internally on the WebAssembly browser side).
- **Encodings are not included:** To keep the binary size minimal, encodings like Base64 or Hex are not part of this package. They are provided as zero-dependency packages in the ecosystem (e.g., `github.com/tinywasm/base64`).

### 1.3 Leaf Subpackages for Non-Stdlib Primitives
The root package (`tinycrypto.go`) is deliberately heavy: it concentrates
`crypto/aes`, `crypto/x509`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/ecdh`
so consumers never import them directly. That means the root package **cannot
be imported by anything that must stay free of Go's `fmt`/`reflect`/`errors`
chain** — Go compiles a package as a single unit, so importing the root for
even a small helper (e.g. random bytes) pulls in everything else it carries.

Primitives that the standard library never shipped (`bcrypt`, `blowfish` —
available only via `golang.org/x/crypto`, whose own dependency chain drags in
`fmt`, `strconv`, `reflect`, `encoding/base64`) are ported into **leaf
subpackages** instead of the root:

```
crypto/subtle/     — constant-time comparison
crypto/blowfish/   — block cipher (bcrypt's building block)
crypto/bcrypt/     — password hashing
crypto/rand/       — entropy, isolated so the leaf packages above never
                      need to import the root package
```

Each leaf subpackage is verified to carry zero disallowed stdlib imports with
`GOOS=js GOARCH=wasm go list -deps ./<pkg>/`, and its binary-size claim is
backed by an actual `tinygo build -target=wasm -no-debug -opt=z` measurement
of a minimal program — see the Binary Size Benchmarks table in `README.md`.
`HMACEqual` in the root package delegates to `crypto/subtle.ConstantTimeCompare`
rather than duplicating the primitive.

## 2. Testing Constraints (Dual Testing Pattern)
To ensure the logic is fully compatible with both executing environments, tests must follow the **WASM/Stlib Dual Testing Pattern**:
1. Business logic of tests is abstracted into a shared runner (`RunCryptoTests`).
2. Two separate test entry files are maintained using appropriate build tags (`//go:build wasm` vs `//go:build !wasm`).
3. Each test entry point delegates execution to the single source of truth in the shared runner.
