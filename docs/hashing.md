# Hashing and MACs

The `crypto` package provides HMAC-SHA256, the standard primitive for
authenticating messages and signing JWT (JSON Web Tokens).

## HMAC-SHA256

Unlike a plain hash, an HMAC (Hash-based Message Authentication Code) uses a
secret key to ensure that a message has not been tampered with and that it
originates from a party possessing the key.

```go
func HMACSHA256(key, message []byte) []byte
```

### Constant-Time Comparison

When verifying a MAC, you **must** use `HMACEqual` to avoid timing attacks. A
standard `==` comparison or a loop that returns early on the first differing
byte creates a timing oracle that allows an attacker to guess the MAC byte by
byte.

```go
func HMACEqual(mac1, mac2 []byte) bool
```

## JWT Signing Example

This is the primary use case for `HMACSHA256` in the TinyWASM ecosystem. Note
that Base64 encoding is handled by the `github.com/tinywasm/base64` package.

```go
import (
	"github.com/tinywasm/base64"
	"github.com/tinywasm/crypto"
)

func SignJWT(header, payload string, key []byte) string {
	// 1. Encode segments
	h := base64.URLEncode([]byte(header))
	p := base64.URLEncode([]byte(payload))

	// 2. Sign "header.payload"
	unsignedToken := h + "." + p
	signature := crypto.HMACSHA256(key, []byte(unsignedToken))

	// 3. Append encoded signature
	return unsignedToken + "." + base64.URLEncode(signature)
}

func VerifyJWT(token string, key []byte) bool {
	// ... split token into unsignedToken and providedSig ...

	expectedSig := crypto.HMACSHA256(key, []byte(unsignedToken))
	providedSig, _ := base64.URLDecode(providedSigEncoded)

	// ALWAYS use HMACEqual for verification
	return crypto.HMACEqual(expectedSig, providedSig)
}
```

## Password Hashing — `crypto/bcrypt`

`crypto/bcrypt` is a stdlib-free port of `golang.org/x/crypto/bcrypt`, built
on top of `crypto/blowfish` (the cipher bcrypt uses internally) and
`crypto/subtle` (constant-time hash comparison). It exists as a leaf
subpackage — see `docs/ARCHITECTURE.md` §1.3 — so that importing it never
pulls stdlib `fmt`/`reflect`/`encoding/base64` into a WASM binary.

```go
func GenerateFromPassword(password []byte, cost int) ([]byte, error)
func CompareHashAndPassword(hashedPassword, password []byte) error
func Cost(hashedPassword []byte) (int, error)
```

Signatures are identical to `golang.org/x/crypto/bcrypt`, and hashes are
interoperable in both directions: a hash produced by `golang.org/x/crypto/bcrypt`
verifies correctly here, and vice versa.

```go
import "github.com/tinywasm/crypto/bcrypt"

hashed, err := bcrypt.GenerateFromPassword([]byte("mysecret"), bcrypt.DefaultCost)
if err != nil {
	panic(err)
}

err = bcrypt.CompareHashAndPassword(hashed, []byte("mysecret"))
// err == nil: password matches
// err == bcrypt.ErrMismatchedHashAndPassword: password does not match
```

`DefaultCost` (10) takes roughly 100 ms per hash by design — that cost is what
makes brute-forcing expensive. Use `bcrypt.MinCost` in tests that are not
specifically measuring cost.
