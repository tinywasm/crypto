# Architecture: TinyWASM Crypto Layer

The `crypto` module is an isomorphic library designed to provide cryptographic capabilities directly to both the backend (Standard Go) and the frontend (WebAssembly via TinyGo).

## 1. Design Philosophy

### 1.1 Direct Package API
The library uses a stateless, direct API approach. Instead of requiring developers to instantiate a struct `crypto.New()`, it exposes plain package-level functions (`crypto.Encrypt`, `crypto.Sign`, etc.). This reduces verbosity, simplifies the code style across the project, and improves ergonomics. 

Because `crypto` handles random entropy generation and pure math evaluation (AES, ECDSA, ECDH), no persistent configuration object (struct instance) is necessary to execute these operations.

### 1.2 Isomorphism and Standards
Both the native backend runtime and the TinyGo WebAssembly runtime implement identical cryptographic algorithms over standard signatures. There is 100% behavioral equivalence.
- The standard library's `crypto` subpackages are used internally, except tailored implementations for entropy collection depending on the environment (e.g., `readRandom` mapping to generic `rand.Read` natively, and to `crypto.getRandomValues()` internally on the WebAssembly browser side).

## 2. Testing Constraints (Dual Testing Pattern)
To ensure the logic is fully compatible with both executing environments, tests must follow the **WASM/Stlib Dual Testing Pattern**:
1. Business logic of tests is abstracted into a shared runner (`RunCryptoTests`).
2. Two separate test entry files are maintained using appropriate build tags (`//go:build wasm` vs `//go:build !wasm`).
3. Each test entry point delegates execution to the single source of truth in the shared runner.
