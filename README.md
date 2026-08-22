# tinywasm/crypto
<img src="docs/img/badges.svg">

A lightweight Go library for cryptographic operations, designed for WebAssembly and small devices using TinyGo.

## Features

- **Simple API:** Easy-to-use API for symmetric and asymmetric encryption, digital signatures, HMAC, constant-time operations, blowfish, and bcrypt.
- **TinyGo Optimized:** Subpackages allow fine-grained imports without pulling unnecessary cipher tables or stdlib packages into applications.
- **WebAssembly Ready:** Can be used in browser environments.
- **Zero Dependencies on Go Standard Library for Core Codecs:** Uses `github.com/tinywasm/fmt` and `github.com/tinywasm/base64`.

## Basic Usage

Import the leaf subpackage for the capability you need — the root package
only provides `Random` (entropy). This is a breaking change: `Encrypt`,
`Sign`, `HMACSHA256`, etc. no longer exist at `github.com/tinywasm/crypto`.

```go
package main

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/crypto/aesgcm"
	"github.com/tinywasm/crypto/asym"
	"github.com/tinywasm/crypto/bcrypt"
)

func main() {
	// Symmetric encryption
	key := make([]byte, 32) // AES-256 key
	plaintext := []byte("hello world")
	ciphertext, err := aesgcm.Encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}
	decrypted, err := aesgcm.Decrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("Symmetric decrypted:", string(decrypted))

	// Password hashing with bcrypt
	hashed, err := bcrypt.GenerateFromPassword([]byte("mysecret"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	err = bcrypt.CompareHashAndPassword(hashed, []byte("mysecret"))
	fmt.Println("Bcrypt verified:", err == nil)

	// Asymmetric signatures
	pub, priv, err := asym.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	message := []byte("this is a test message")
	signature, err := asym.Sign(message, priv)
	if err != nil {
		panic(err)
	}
	ok, err := asym.Verify(message, signature, pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature verified:", ok)
}
```

## Binary Size Benchmarks (TinyGo WebAssembly)

Every number below is a minimal standalone program compiled with
`tinygo build -target=wasm -no-debug -opt=z` (TinyGo 0.41.1, Go 1.25.2,
LLVM 20.1.1), measured on 2026-08-22. Reproduce with the recipe in
[docs/TINYGO_COMPATIBILITY.md](./docs/TINYGO_COMPATIBILITY.md).

**Password hashing — why `crypto/bcrypt` exists:**

| Minimal program | Binary |
|---|---|
| `bcrypt.GenerateFromPassword` (`tinywasm/crypto/bcrypt`) | **65,748 bytes** |
| `bcrypt.GenerateFromPassword` (`golang.org/x/crypto/bcrypt`) | 186,307 bytes |

`tinywasm/crypto/bcrypt` pulls none of `fmt`, `strconv`, `errors`, `io`,
`bytes`, `unicode`, `reflect` or `encoding/base64` — **65% smaller**, and
hash-compatible in both directions with `golang.org/x/crypto/bcrypt`.

**Import cost by entry point — read this before choosing an import:**

| Minimal program | Binary |
|---|---|
| empty `main` (toolchain floor) | 21,731 bytes |
| `subtle` / `blowfish` / `bcrypt` / `rand` leaf subpackages | 65,748 bytes (bcrypt, the largest) |
| `hmac.HMACSHA256` (`github.com/tinywasm/crypto/hmac`) | 155,260 bytes |
| `crypto/hmac` + `crypto/sha256` called directly (stdlib) | 155,246 bytes |
| `aesgcm.Encrypt` (`github.com/tinywasm/crypto/aesgcm`) | 164,988 bytes |
| `asym` (`github.com/tinywasm/crypto/asym` — GenerateKeyPair/Sign/Verify) | 1,011,877 bytes |

> **Breaking change:** the root package `github.com/tinywasm/crypto` no longer
> re-exports `HMACSHA256`, `Encrypt`, `Sign`, etc. Importing it for HMAC
> previously cost ~264 KB because it linked `crypto/x509` (`net`,
> `encoding/pem`, `encoding/asn1`, `math/big`, `fmt`, `reflect`) — ~109 KB no
> consumer needed. Import the leaf you call (`crypto/hmac`, `crypto/aesgcm`,
> `crypto/asym`, `crypto/bcrypt`, `crypto/blowfish`, `crypto/subtle`,
> `crypto/rand`) and you link exactly what you use.

## Documentation

The detailed API documentation is organized into the following sections:

- [Symmetric Encryption](./docs/symmetric.md)
- [Asymmetric Encryption](./docs/asymmetric.md)
- [Digital Signatures](./docs/signatures.md)
- [Hashing and MACs](./docs/hashing.md)
- [Architecture Details](./docs/ARCHITECTURE.md)
- [Implementation Guide](./docs/IMPLEMENTATION.md)
- [TinyGo Compatibility](./docs/TINYGO_COMPATIBILITY.md)
