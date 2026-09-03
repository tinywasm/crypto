package rand

import . "github.com/tinywasm/fmt"

// maxChunk is the maximum byte count crypto.getRandomValues accepts per call
// (WebCrypto throws QuotaExceededError above this limit).
const maxChunk = 65536

// ErrNoCSPRNG indicates the environment does not expose a cryptographic generator.
var ErrNoCSPRNG = Err("rand", "csprng", "unavailable")

// ErrCSPRNGFailed indicates the generator exists but rejected the request.
var ErrCSPRNGFailed = Err("rand", "csprng", "failed")

// ErrInvalidLength indicates a non-positive byte count was requested.
var ErrInvalidLength = Err("rand", "length", "must-be-positive")
