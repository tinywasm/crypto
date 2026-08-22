package blowfish

import (
	. "github.com/tinywasm/fmt"
)

// BlockSize is the Blowfish block size in bytes (8 bytes).
const BlockSize = 8

// ErrKeySize is the error returned when the key has an invalid size.
const ErrKeySize = "blowfish: invalid key size"

// Cipher is an instance of the Blowfish cipher.
type Cipher struct {
	p              [18]uint32
	s0, s1, s2, s3 [256]uint32
}

// NewCipher creates and returns a Cipher.
// The key must be between 1 and 56 bytes long.
func NewCipher(key []byte) (*Cipher, error) {
	if k := len(key); k < 1 || k > 56 {
		return nil, Err(ErrKeySize)
	}
	var result Cipher
	initCipher(&result)
	ExpandKey(key, &result)
	return &result, nil
}

// NewSaltedCipher creates and returns a Cipher that folds a salt into its
// key schedule. For bcrypt compatibility, the key may exceed 56 bytes.
func NewSaltedCipher(key, salt []byte) (*Cipher, error) {
	if len(salt) == 0 {
		return NewCipher(key)
	}
	if len(key) < 1 {
		return nil, Err(ErrKeySize)
	}
	var result Cipher
	initCipher(&result)
	expandKeyWithSalt(key, salt, &result)
	return &result, nil
}

// Encrypt encrypts the 8-byte block src and stores the result in dst.
func (c *Cipher) Encrypt(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = encryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

// Decrypt decrypts the 8-byte block src and stores the result in dst.
func (c *Cipher) Decrypt(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = decryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

func initCipher(c *Cipher) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
}

func getNextWord(b []byte, pos *int) uint32 {
	var w uint32
	j := *pos
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	*pos = j
	return w
}

// ExpandKey performs the key expansion on the given Cipher.
func ExpandKey(key []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func expandKeyWithSalt(key []byte, salt []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getNextWord(key, &j)
	}

	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func encryptBlock(l, r uint32, c *Cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[1]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[2]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[3]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[4]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[5]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[6]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[7]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[8]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[9]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[10]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[11]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[12]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[13]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[14]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[15]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[16]
	xr ^= c.p[17]
	return xr, xl
}

func decryptBlock(l, r uint32, c *Cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[17]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[16]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[15]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[14]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[13]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[12]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[11]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[10]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[9]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[8]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[7]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[6]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[5]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[4]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[3]
	xr ^= ((c.s0[byte(xl>>24)] + c.s1[byte(xl>>16)]) ^ c.s2[byte(xl>>8)]) + c.s3[byte(xl)] ^ c.p[2]
	xl ^= ((c.s0[byte(xr>>24)] + c.s1[byte(xr>>16)]) ^ c.s2[byte(xr>>8)]) + c.s3[byte(xr)] ^ c.p[1]
	xr ^= c.p[0]
	return xr, xl
}
