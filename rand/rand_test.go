package rand_test

import (
	"bytes"
	"testing"

	"github.com/tinywasm/crypto/rand"
)

func TestRead(t *testing.T) {
	b1 := make([]byte, 16)
	b2 := make([]byte, 16)

	if err := rand.Read(b1); err != nil {
		t.Fatalf("rand.Read(b1) failed: %v", err)
	}
	if err := rand.Read(b2); err != nil {
		t.Fatalf("rand.Read(b2) failed: %v", err)
	}

	if bytes.Equal(b1, b2) {
		t.Errorf("expected different random bytes, got identical: %v", b1)
	}
}
