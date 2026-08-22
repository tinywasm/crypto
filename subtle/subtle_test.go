package subtle_test

import (
	"testing"

	"github.com/tinywasm/crypto/subtle"
)

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		x, y []byte
		want int
	}{
		{[]byte("hello"), []byte("hello"), 1},
		{[]byte("hello"), []byte("world"), 0},
		{[]byte("hello"), []byte("hell"), 0},
		{[]byte("hell"), []byte("hello"), 0},
		{[]byte("hello"), []byte("xello"), 0},
		{[]byte("hello"), []byte("hellx"), 0},
		{[]byte(""), []byte(""), 1},
		{[]byte{}, []byte{}, 1},
	}

	for _, tt := range tests {
		got := subtle.ConstantTimeCompare(tt.x, tt.y)
		if got != tt.want {
			t.Errorf("ConstantTimeCompare(%q, %q) = %d; want %d", tt.x, tt.y, got, tt.want)
		}
	}
}

func TestConstantTimeByteEq(t *testing.T) {
	for x := 0; x <= 255; x++ {
		for y := 0; y <= 255; y++ {
			want := 0
			if x == y {
				want = 1
			}
			got := subtle.ConstantTimeByteEq(uint8(x), uint8(y))
			if got != want {
				t.Errorf("ConstantTimeByteEq(%d, %d) = %d; want %d", x, y, got, want)
			}
		}
	}
}
