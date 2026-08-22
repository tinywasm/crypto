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

Stateless, package-level functions (`crypto.Encrypt`, `crypto.Sign`,
`crypto.HMACSHA256`). **No** constructor, **no** config struct, **no** receiver:
this library does entropy generation and pure math, so it holds no state.

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
re-implementing primitives in Go would be both slower and less safe. This is
the whole point of the package: it is the one place where crypto stdlib is
concentrated, so that **consumers never import it**.

That carve-out does **not** extend to anything else. No `encoding/*`, no
`strings`, no `strconv`, no `errors`, no `time`, no `fmt`. Encodings
(base64url, hex) are implemented in-repo over `[]byte`.

**Never roll your own primitive if it is in the Go standard library.** No
hand-written SHA/AES/HMAC compression loops — call the stdlib `crypto/*`
implementation. This does **not** cover primitives the standard library never
shipped (bcrypt, blowfish): those live only in `golang.org/x/crypto`, which
pulls in `fmt`/`errors`/`reflect` through its own dependency chain, so they
are ported into leaf subpackages instead — see "Leaf subpackages" below.

## Leaf subpackages — the pattern for anything the root package can't carry

The root package (`tinycrypto.go`) already imports `crypto/aes`, `crypto/x509`,
`crypto/ecdsa`, `crypto/elliptic`, `crypto/ecdh` — real weight. Any new
primitive that must stay stdlib-free (no `fmt`, `strconv`, `errors`, `io`,
`bytes`, `unicode`, `reflect`, `encoding/base64`) **cannot import the root
package**, even for something as small as random bytes: Go compiles a package
as one unit, so one import of `github.com/tinywasm/crypto` drags in
everything the root carries.

Established leaf subpackages, each with zero non-test stdlib imports from the
forbidden list (verify with `GOOS=js GOARCH=wasm go list -deps ./<pkg>/`):

- `crypto/subtle` — `ConstantTimeCompare`, `ConstantTimeByteEq`.
- `crypto/blowfish` — block cipher, ported from `golang.org/x/crypto/blowfish`.
- `crypto/bcrypt` — password hashing, ported from `golang.org/x/crypto/bcrypt`.
- `crypto/rand` — `Read(b []byte) error`, the entropy source these packages
  use instead of the root's `Random`. The root's `Random` is a thin re-export
  of `crypto/rand.Read` for existing callers — new stdlib-free code should
  import `crypto/rand` directly, not the root package.

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
