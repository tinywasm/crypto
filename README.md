# tinywasm/crypto
<img src="docs/img/badges.svg">

A lightweight Go library for cryptographic operations, designed for WebAssembly and small devices using TinyGo.

## Features

- **Simple API:** Easy-to-use API for symmetric and asymmetric encryption, digital signatures, HMAC, constant-time operations, blowfish, and bcrypt.
- **TinyGo Optimized:** Subpackages allow fine-grained imports without pulling unnecessary cipher tables into HMAC-only applications.
- **WebAssembly Ready:** Can be used in browser environments.
- **Zero Dependencies on Go Standard Library for Core String/Error Codecs:** Uses `github.com/tinywasm/fmt` and `github.com/tinywasm/base64`.

## Basic Usage

To use the library, import the package and call its functions directly:

```go
package main

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/crypto"
	"github.com/tinywasm/crypto/bcrypt"
)

func main() {
	// Symmetric encryption
	key := make([]byte, 32) // AES-256 key
	plaintext := []byte("hello world")
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}
	decrypted, err := crypto.Decrypt(ciphertext, key)
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
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	message := []byte("this is a test message")
	signature, err := crypto.Sign(message, priv)
	if err != nil {
		panic(err)
	}
	ok, err := crypto.Verify(message, signature, pub)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature verified:", ok)
}
```

## Binary Size Benchmarks (TinyGo WebAssembly)

Minimal standalone programs compiled with `tinygo build -target=wasm -no-debug -opt=z`:

| Package / Operation | Compiled Size (WASM) |
|---|---|
| `crypto.HMACSHA256` | **264,575 bytes** |
| `bcrypt.GenerateFromPassword` (`tinywasm/crypto/bcrypt`) | **285,376 bytes** |
| `bcrypt.GenerateFromPassword` (`golang.org/x/crypto/bcrypt`) | **186,185 bytes** |

*Note: In full application binaries where standard library reflection (`fmt`, `strconv`, `unicode`) is avoided, `tinywasm/crypto/bcrypt` prevents pulling in Go stdlib dependencies.*

## Documentation

The detailed API documentation is organized into the following sections:

- [Symmetric Encryption](./docs/symmetric.md)
- [Asymmetric Encryption](./docs/asymmetric.md)
- [Digital Signatures](./docs/signatures.md)
- [Hashing and MACs](./docs/hashing.md)
- [Architecture Details](./docs/ARCHITECTURE.md)
- [Implementation Guide](./docs/IMPLEMENTATION.md)
- [TinyGo Compatibility](./docs/TINYGO_COMPATIBILITY.md)
