# Agent Guide — `tinywasm/crypto`

Constraints for agents working on this library. Read this before any change.

---

## What this library is

An **isomorphic** cryptographic layer: the same API compiles and behaves
identically on the native backend (standard Go) and on the frontend/edge
(WebAssembly via TinyGo — browsers, Cloudflare Workers, `goflare`). Consumers
such as `tinywasm/user` sign and verify tokens with it inside a WASM binary,
so **binary size is a design constraint, not a detail**.

## Public API shape — direct package functions

Stateless, package-level functions per leaf (`aesgcm.Encrypt`, `asym.Sign`,
`hmac.HMACSHA256`; root only `crypto.Random`). **No** constructor, **no** config
struct, **no** receiver: this library does entropy generation and pure math, so
it holds no state.

- **Typed over `any`** — zero generics, zero `any`, zero `map` in the public
  API (the `tinywasm/fmt` codec rule: *"cero any, cero map"*).
- **Minimal public surface** — export only what consumers call. Helpers stay
  unexported.
- Inputs and outputs are `[]byte` / `string`; errors propagate as values.

## The stdlib rule — and its one carve-out

The ecosystem rule is *no Go stdlib* (use `github.com/tinywasm/fmt` for
strings, numbers and errors; it is dot-imported here:
`. "github.com/tinywasm/fmt"`).

**Carve-out:** the `crypto/*` standard packages (`crypto/aes`, `crypto/cipher`,
`crypto/ecdh`, `crypto/ecdsa`, `crypto/sha256`, `crypto/hmac`, `crypto/rand`,
`crypto/subtle`, `crypto/x509`) **are allowed and expected inside this
library** — they are TinyGo-supported, constant-time where it matters, and
re-implementing primitives in Go would be both slower and less safe.

⚠️ **The carve-out says WHICH implementation to call, never WHERE to put it.**
An earlier version of this guide read "it is the one place where crypto stdlib
is concentrated, so that consumers never import it" — **that was wrong, and it
is what bloated the root package.** Concentrating every primitive into one Go
package makes every consumer pay for the heaviest member of it, because Go
links a package as a unit: importing the root for `HMACSHA256` links
`crypto/x509`, and x509 drags `net`, `encoding/pem`, `encoding/asn1`,
`math/big`, `fmt` and `reflect` with it.

Measured (`tinygo build -target=wasm -no-debug -opt=z`, TinyGo 0.41.1):

| Minimal program | Binary |
|---|---|
| empty `main` (floor) | 21 731 B |
| `crypto/hmac` + `crypto/sha256` called directly | 155 534 B |
| the same HMAC through `crypto.HMACSHA256` (root pkg) | **264 638 B** |

**A consumer that only signs JWTs pays ~109 KB for X.509, PEM and ASN.1 it
never calls.** That is the same 109 KB the bcrypt plan was written to remove
from `veltylabs/misitio` — reintroduced by the library meant to prevent it.

The correct doctrine is the one in "Leaf subpackages" below: **the root
package must be as light as any leaf.** Grouping is by what a consumer imports
together, not by "it's all crypto".

That carve-out does **not** extend to anything else. No `encoding/*`, no
`strings`, no `strconv`, no `errors`, no `time`, no `fmt`. Encodings
(base64url, hex) are implemented in-repo over `[]byte`.

**Never roll your own primitive if it is in the Go standard library.** No
hand-written SHA/AES/HMAC compression loops — call the stdlib `crypto/*`
implementation. This does **not** cover primitives the standard library never
shipped (bcrypt, blowfish): those live only in `golang.org/x/crypto`, which
pulls in `fmt`/`errors`/`reflect` through its own dependency chain, so they
are ported into leaf subpackages instead — see "Leaf subpackages" below.

## Leaf subpackages — the default, not the exception

**Every new capability goes in its own leaf subpackage.** The root package
only exposes `Random` — it is not a home for new code and no longer re-exports
`Encrypt`, `Sign` or `HMACSHA256` (breaking change; import the leaf instead).
Anything that must stay free of `fmt`, `strconv`, `errors`, `io`, `bytes`,
`unicode`, `reflect`, `encoding/base64` **cannot import the root package**
for crypto, even before the break: Go compiles a package as one unit.

Established leaf subpackages, each with zero non-test stdlib imports from the
forbidden list (verify with `GOOS=js GOARCH=wasm go list -deps ./<pkg>/`):

- `crypto/subtle` — `ConstantTimeCompare`, `ConstantTimeByteEq`.
- `crypto/blowfish` — block cipher, ported from `golang.org/x/crypto/blowfish`.
- `crypto/bcrypt` — password hashing, ported from `golang.org/x/crypto/bcrypt`.
- `crypto/rand` — `Read(b []byte) error`, the **single entropy source for the
  whole library**. The root's `Random` is a thin re-export of it, and the root
  feeds it to `ecdsa`/`ecdh` through the tiny `randReader` `io.Reader` adapter
  (now in `asym/asym.go`) rather than importing stdlib `crypto/rand` a second time.
  New stdlib-free code imports `crypto/rand` directly, never the root package.

  Note the adapter buys clarity, not bytes: `crypto/x509` imports stdlib
  `crypto/rand` unconditionally, so while the root still uses x509 the stdlib
  CSPRNG is linked either way (measured: byte-identical, 264 638 B before and
  after). One entropy path is still the right invariant — it is what makes the
  browser/native split auditable in one place.
- `crypto/hmac` — `HMACSHA256`, `HMACEqual` (`crypto/hmac`, `crypto/sha256`).
- `crypto/aesgcm` — `Encrypt`, `Decrypt` (`crypto/aes`, `crypto/cipher`).
- `crypto/asym` — `GenerateKeyPair`, `Sign`, `Verify`, `EncryptAsymmetric`,
  `DecryptAsymmetric` (`crypto/ecdsa`, `crypto/ecdh`, `crypto/x509` — the
  only leaf that carries `crypto/x509` by design; anyone serializing a key
  pair already accepts that dependency).

**Measure, don't assume:** the first attempt at `crypto/bcrypt` imported the
root package for randomness and shipped a TinyGo binary 53% *larger* than
`golang.org/x/crypto/bcrypt` — the opposite of the point. Always confirm a new
leaf subpackage with an actual `tinygo build -target=wasm -no-debug -opt=z` of
a minimal program, not just `go list -deps`.

## Environment-specific code

Entropy is the only thing that differs per environment, and it is isolated by
build tag inside `crypto/rand`:

- `rand/rand_native.go` (`//go:build !wasm`) → `crypto/rand` (stdlib).
- `rand/rand_wasm.go` (`//go:build wasm`) → `crypto.getRandomValues()` via
  `syscall/js`.

The root package's `random.go` (no build tag) re-exports
`github.com/tinywasm/crypto/rand.Read` as `Random(b []byte) error` for
backward compatibility with existing callers.

Everything else is tag-free and must compile for **both** targets. `syscall/js`
appears **only** in `*_wasm.go` files.

## Constant time

Any comparison of a secret, a MAC or a signature MUST be constant-time
(`crypto/hmac.Equal` or `crypto/subtle.ConstantTimeCompare`). A byte-by-byte
`==`, `bytes.Equal`, or an early `return false` on the first differing byte is
a **timing oracle** and will be rejected in review.

## Testing — dual WASM/stdlib pattern

```bash
go install github.com/tinywasm/devflow/cmd/gotest@latest
gotest          # runs BOTH suites: native + wasm (Go toolchain)
gotest -tinygo  # compiles the WASM suite with TinyGo (slow: ~2 min, goes through LLVM)
```

`gotest`, never `go test`.

**Plain `gotest` cannot prove TinyGo compatibility.** It builds the WASM suite
with the *Go* toolchain (`GOOS=js GOARCH=wasm`), whose backend supports the full
stdlib — so a package TinyGo would reject still shows a green `wasm ✅`. Since
this library's whole promise is that it runs under TinyGo, **any change that adds
or removes an import must be checked with `gotest -tinygo`**. See
`docs/TINYGO_COMPATIBILITY.md`.

The dual-environment pattern is mandatory and already in place:

1. All test logic lives in a shared runner in `shared_test.go`
   (`func RunCryptoTests(t *testing.T)`), which registers every subtest with
   `t.Run(...)`.
2. Two thin entry points delegate to it:
   - `backStlib_test.go` (`//go:build !wasm`) → `TestCrypto_Native`.
   - `frontWasm_test.go` (`//go:build wasm`) → `TestCrypto_WASM`.

**A new test is added as a `test_XxxYyy` function registered inside
`RunCryptoTests` — never as a bare top-level `TestXxx`**, or it will run in
only one of the two environments.

- Stdlib assertions only (`testing`); no assertion library, no mocks.
- Crypto is verified with **known-answer vectors from the RFC**, not just
  round-trips: a round-trip alone passes even if both directions are wrong in
  the same way.

## Documentation first

Update docs **before** the code lands: `docs/ARCHITECTURE.md` (design
philosophy, isomorphism, testing constraints), the per-topic pages
(`docs/symmetric.md`, `docs/asymmetric.md`, `docs/signatures.md`, …), and
re-index `README.md` so every file under `docs/` is linked. Diagrams are
`flowchart TD`, no `subgraph`, `<br/>` for line breaks. English only.

## Never

- Never call `gopush` or `codejob` — local developer tooling, outside the agent.
- Never change an existing function's signature or algorithm without it being
  ordered by `docs/PLAN.md`: consumers (`tinywasm/user`) sign persisted data
  with them, and a silent format change invalidates stored credentials/tokens.
- Never write Spanish in code comments or error strings, even if a
  `docs/PLAN.md` instructs otherwise — a plan's own language is not a source
  of code convention. This repo is English throughout, code and comments
  alike; the sole exception is `docs/TINYGO_COMPATIBILITY.md`, Spanish by its
  own explicit header note.
