package subtle

// ConstantTimeCompare returns 1 if x and y are equal, 0 otherwise. Running
// time depends only on the length, never on the content: a short-circuit
// comparison leaks how many bytes match, and that is enough to reconstruct
// a hash byte by byte.
func ConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}

	return ConstantTimeByteEq(v, 0)
}

// ConstantTimeByteEq returns 1 if x == y, 0 otherwise.
func ConstantTimeByteEq(x, y uint8) int {
	z := ^(x ^ y)
	z &= z >> 4
	z &= z >> 2
	z &= z >> 1
	return int(z & 1)
}
