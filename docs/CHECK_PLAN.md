---
message: "feat: HMAC-SHA256 and constant-time MAC comparison"
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.

# PLAN — HMAC-SHA256: the JWT signing primitive

## Context (zero-context summary)

`github.com/tinywasm/crypto` is the tinywasm ecosystem's **isomorphic** crypto
layer: identical API and behavior on native Go and on WebAssembly/TinyGo
(browsers, Cloudflare Workers, `goflare`). It ships AES-GCM symmetric
encryption, ECDH asymmetric encryption and ECDSA signatures as stateless,
package-level functions (`crypto.Encrypt`, `crypto.Sign`, …).

**Read [`AGENTS.md`](../AGENTS.md) at the repo root before touching code** — it
carries the binding constraints (stdlib carve-out, dual-test pattern,
constant-time rule). The essentials are restated inline below; you do not need
to read anything else.

### Why this plan exists

`github.com/tinywasm/user` is an authentication library that runs on the edge.
Its `server/jwt.go` currently signs and validates session tokens with the Go
standard library directly — `crypto/hmac`, `crypto/sha256` and
`encoding/base64` — which is exactly what consumers must never do: every stdlib
import lands in the WASM binary, and the ecosystem concentrates crypto in *this*
package so that no one else imports `crypto/*`.

`tinywasm/user` cannot complete its own migration until this package exposes the
JWT primitives. **This plan is a blocking gate for that work**, and the API
below is a contract already agreed with the consumer — implement it exactly as
specified, do not rename, do not "improve" the signatures.

## The contract

```go
// HMACSHA256 returns the HMAC-SHA256 of message under key.
func HMACSHA256(key, message []byte) []byte

// HMACEqual reports whether two MACs are equal, in constant time.
func HMACEqual(mac1, mac2 []byte) bool
```

**Base64 is NOT part of this plan.** It already ships as its own zero-dependency
package, `github.com/tinywasm/base64` (`URLEncode` / `URLDecode`, unpadded
RFC 4648 §5 — the encoding JWT uses). Consumers import it directly; do **not**
add a base64 wrapper to this package, and do not import it here — nothing in
`crypto` needs it.

## Constraints (from AGENTS.md — violating any of these fails review)

- **No Go stdlib**, with one carve-out: the `crypto/*` packages are allowed and
  expected **inside this library** (that is its purpose). `crypto/hmac` and
  `crypto/sha256` are therefore the correct implementation for `HMACSHA256` —
  **never hand-roll a compression loop.**
- The carve-out does **not** extend to `encoding/*`. Base64 already lives in
  `github.com/tinywasm/base64` (see [TINYGO_COMPATIBILITY.md](TINYGO_COMPATIBILITY.md)
  for the measurements behind that split); it is not needed here.
- `crypto/hmac` and `crypto/sha256` were verified to compile under TinyGo 0.41.1
  — use them, do not reimplement them.
- **Neither function returns an `error`, and neither may start doing so.** HMAC
  is total: it is defined for a key of any length and a message of any length,
  so there is no failure mode to report. Do not add an `error` return, a
  key-length check, or a `fmt.Err` value — the signatures are a contract already
  agreed with the consumer. (This is why `tinywasm/fmt`, which the package
  dot-imports as `. "github.com/tinywasm/fmt"`, plays no part in this plan.)
- The new files carry **no build tag**: they must compile for native *and*
  wasm. `syscall/js` appears only in `*_wasm.go`.
- Zero generics, zero `any`, zero `map` in the public API.

## Stage 1 — `hmac.go` (new file)

```go
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 returns the HMAC-SHA256 of message under key.
// Used by tinywasm/user to sign JWT session tokens.
func HMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// HMACEqual reports whether two MACs are equal, in constant time.
// A non-constant-time comparison of a MAC is a timing oracle: never
// compare signatures with == or a byte loop that returns early.
func HMACEqual(mac1, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}
```

That is the whole stage — resist adding options, key-length checks or a
`Hash` parameter. HMAC is defined for keys of any length; truncating or
rejecting them would break the consumer.

## Stage 2 — tests (`shared_test.go`)

Register the new subtests **inside the existing runner** — do not add top-level
`TestXxx` functions, or they will run in only one of the two environments:

```go
func RunCryptoTests(t *testing.T) {
	// ... existing subtests, untouched ...
	t.Run("HMACSHA256", test_HMACSHA256)
	t.Run("HMACEqual", test_HMACEqual)
}
```

**Known-answer vectors are mandatory** — a round-trip alone passes even when
both directions are wrong in the same way.

- `test_HMACSHA256` — RFC 4231 test case 1: key = 20 bytes of `0x0b`,
  message = `"Hi There"`, expected MAC (hex):

  ```
  b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  ```

  Assert the length is 32 bytes, and that a one-bit change in the message
  produces a different MAC.

- `test_HMACEqual` — equal MACs → `true`; MACs differing in the last byte →
  `false`; different lengths → `false`.

Run the suite (it executes both environments), and prove it under the compiler
that actually ships to the edge:

```bash
go install github.com/tinywasm/devflow/cmd/gotest@latest
gotest
gotest -tinygo   # compiles the WASM suite with TinyGo (slow, ~2min — required here)
```

## Stage 3 — documentation

- `docs/hashing.md` (new): the HMAC surface, with a worked example of signing and
  verifying a `header.payload` string — the JWT use case that motivated it. Show
  `github.com/tinywasm/base64` (`URLEncode`/`URLDecode`) providing the segment
  encoding, and state plainly that the signature comparison must go through
  `HMACEqual`, never `==`.
- `docs/ARCHITECTURE.md`: add HMAC-SHA256 to the capability list; record that
  encodings are **not** part of this package (base64 lives in
  `github.com/tinywasm/base64`) — the stdlib carve-out covers cryptographic
  primitives only.
- `README.md`: link `docs/hashing.md` **and** `docs/TINYGO_COMPATIBILITY.md` in
  the documentation index, and mention the new functions in the feature list.
- After implementing, re-run `gotest -tinygo` and update the compatibility table
  in `docs/TINYGO_COMPATIBILITY.md`: the `crypto/hmac` row moves from *pendiente*
  to delivered (`hmac.go`). Leave the `crypto/subtle` row as it is — this plan
  does not import it (`hmac.Equal` is already the constant-time comparison), it
  is listed there only as a verified-compatible option for the future.
- Do **not** create an `AGENTS.md` — it already exists at the repo root.

## Harness checklist (mandatory)

- `grep -rn "encoding/base64\|\"strings\"\|\"errors\"\|\"strconv\"" --include=*.go .`
  → **empty** in non-test files.
- New files carry no build tag and no `syscall/js`.
- No existing exported function changes signature or behavior: `Encrypt`,
  `Decrypt`, `GenerateKeyPair`, `EncryptAsymmetric`, `DecryptAsymmetric`,
  `Sign`, `Verify` stay exactly as they are. Consumers have persisted data
  signed with them.
- No `map`, no generics, no `any` in the public API.
- If an RFC vector fails, the implementation is wrong — never adjust the
  expected value to match the output.

## Acceptance criteria

1. `gotest` green — native **and** wasm suites — and `gotest -tinygo` green.
2. The two contract functions exist with exactly the specified signatures.
3. The RFC 4231 HMAC known-answer vector passes.
4. MAC comparison is constant-time (`HMACEqual` delegates to `hmac.Equal`).
5. No base64 code is added to this package.
6. README / ARCHITECTURE / `docs/hashing.md` updated as specified.

## Stages

| Stage | File(s) | Action |
|---|---|---|
| 1 | `hmac.go` (new) | `HMACSHA256` + constant-time `HMACEqual` over `crypto/hmac` |
| 2 | `shared_test.go` | subtests registered in `RunCryptoTests`; RFC 4231 known-answer vector |
| 3 | `docs/hashing.md` (new), `docs/ARCHITECTURE.md`, `README.md` | document the JWT primitive; point at `tinywasm/base64` for encoding |

## Downstream (context only — do NOT implement here)

Once published, `tinywasm/user` rewrites `server/jwt.go` to use `HMACSHA256` +
`HMACEqual` and `github.com/tinywasm/base64`, dropping `crypto/hmac`,
`crypto/sha256` and `encoding/base64`. No change in this repo depends on that;
do not open PRs against `tinywasm/user`.
