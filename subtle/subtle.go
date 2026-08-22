package subtle

// ConstantTimeCompare devuelve 1 si x e y son iguales, 0 si no. El tiempo de
// ejecución depende sólo de la longitud, nunca del contenido: comparar con un
// cortocircuito filtra por cuántos bytes coinciden y con eso se reconstruye un
// hash byte a byte.
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

// ConstantTimeByteEq devuelve 1 si x == y, 0 si no.
func ConstantTimeByteEq(x, y uint8) int {
	z := ^(x ^ y)
	z &= z >> 4
	z &= z >> 2
	z &= z >> 1
	return int(z & 1)
}
