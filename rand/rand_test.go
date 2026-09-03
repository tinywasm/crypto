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

func TestBytesRejectsNonPositive(t *testing.T) {
	b0, err0 := rand.Bytes(0)
	if err0 != rand.ErrInvalidLength {
		t.Errorf("expected ErrInvalidLength for 0, got %v", err0)
	}
	if b0 != nil {
		t.Errorf("expected nil slice for 0, got %v", b0)
	}

	bNeg, errNeg := rand.Bytes(-1)
	if errNeg != rand.ErrInvalidLength {
		t.Errorf("expected ErrInvalidLength for -1, got %v", errNeg)
	}
	if bNeg != nil {
		t.Errorf("expected nil slice for -1, got %v", bNeg)
	}
}

func TestBytesLength(t *testing.T) {
	lengths := []int{1, 32, 65537}
	for _, l := range lengths {
		b, err := rand.Bytes(l)
		if err != nil {
			t.Fatalf("Bytes(%d) failed: %v", l, err)
		}
		if len(b) != l {
			t.Errorf("expected length %d, got %d", l, len(b))
		}
	}
}

func TestBytesNotAllZero(t *testing.T) {
	b1, err1 := rand.Bytes(32)
	if err1 != nil {
		t.Fatalf("Bytes(32) failed: %v", err1)
	}
	b2, err2 := rand.Bytes(32)
	if err2 != nil {
		t.Fatalf("Bytes(32) failed: %v", err2)
	}

	zeroBuf := make([]byte, 32)
	if bytes.Equal(b1, zeroBuf) {
		t.Errorf("b1 is all zero bytes")
	}
	if bytes.Equal(b2, zeroBuf) {
		t.Errorf("b2 is all zero bytes")
	}
	if bytes.Equal(b1, b2) {
		t.Errorf("b1 and b2 are identical")
	}
}
