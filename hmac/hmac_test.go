package hmac_test

import (
	"bytes"
	"testing"

	"github.com/tinywasm/crypto/hmac"
)

func TestHMACSHA256(t *testing.T) {
	// RFC 4231 test case 1
	key := bytes.Repeat([]byte{0x0b}, 20)
	message := []byte("Hi There")
	expected := []byte{
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
	}

	mac := hmac.HMACSHA256(key, message)

	if len(mac) != 32 {
		t.Errorf("expected MAC length 32, got %d", len(mac))
	}

	if !bytes.Equal(mac, expected) {
		t.Errorf("MAC mismatch\nexpected: %x\ngot:      %x", expected, mac)
	}

	// One-bit change in message produces different MAC
	message[0] ^= 0x01
	mac2 := hmac.HMACSHA256(key, message)
	if bytes.Equal(mac, mac2) {
		t.Error("MAC should change when message changes")
	}
}

func TestHMACEqual(t *testing.T) {
	mac1 := []byte("this is a mac")
	mac2 := []byte("this is a mac")

	if !hmac.HMACEqual(mac1, mac2) {
		t.Error("HMACEqual should return true for equal MACs")
	}

	// Differing in the last byte
	mac3 := []byte("this is a mad")
	if hmac.HMACEqual(mac1, mac3) {
		t.Error("HMACEqual should return false for different MACs")
	}

	// Different lengths
	mac4 := []byte("this is a mac ")
	if hmac.HMACEqual(mac1, mac4) {
		t.Error("HMACEqual should return false for MACs of different lengths")
	}
}
