package bcrypt

import (
	"github.com/tinywasm/base64"
	. "github.com/tinywasm/fmt"
	"github.com/tinywasm/crypto"
	"github.com/tinywasm/crypto/blowfish"
	"github.com/tinywasm/crypto/subtle"
)

const (
	MinCost     int = 4
	MaxCost     int = 31
	DefaultCost int = 10
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrHashTooShort              Error = "bcrypt: el hash es demasiado corto"
	ErrMismatchedHashAndPassword Error = "bcrypt: el hash no corresponde a la contraseña"
	ErrCostTooLow                      = "bcrypt: coste %d por debajo del mínimo %d"
	ErrCostTooHigh                     = "bcrypt: coste %d por encima del máximo %d"
	ErrHashVersionTooNew               = "bcrypt: versión de hash '%c' no soportada"
	ErrPasswordTooLong           Error = "bcrypt: la contraseña supera los 72 bytes"
	ErrInvalidHashPrefix               = "bcrypt: los hashes deben comenzar con '$', pero comienza con '%c'"
)

const (
	alphabet           = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	majorVersion       = '2'
	minorVersion       = 'a'
	maxSaltSize        = 16
	maxCryptedHashSize = 23
	encodedSaltSize    = 22
	encodedHashSize    = 31
	minHashSize        = 59
)

var bcEncoding *base64.Encoding

func init() {
	var err error
	bcEncoding, err = base64.NewEncoding(alphabet, false)
	if err != nil {
		panic(err)
	}
}

func base64Encode(src []byte) []byte {
	return []byte(bcEncoding.Encode(src))
}

func base64Decode(src []byte) ([]byte, error) {
	return bcEncoding.Decode(string(src))
}

var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

type hashed struct {
	hash  []byte
	salt  []byte
	cost  int
	major byte
	minor byte
}

// GenerateFromPassword devuelve el hash bcrypt de la contraseña al coste dado.
func GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	if len(password) > 72 {
		return nil, ErrPasswordTooLong
	}
	p, err := newFromPassword(password, cost)
	if err != nil {
		return nil, err
	}
	return p.Hash(), nil
}

// CompareHashAndPassword compara un hash bcrypt con una posible contraseña en claro.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return err
	}

	otherHash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return err
	}

	otherP := &hashed{otherHash, p.salt, p.cost, p.major, p.minor}
	if subtle.ConstantTimeCompare(p.Hash(), otherP.Hash()) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

// Cost devuelve el coste utilizado para crear el hash dado.
func Cost(hashedPassword []byte) (int, error) {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return 0, err
	}
	return p.cost, nil
}

func newFromPassword(password []byte, cost int) (*hashed, error) {
	if cost < MinCost {
		cost = DefaultCost
	}
	p := new(hashed)
	p.major = majorVersion
	p.minor = minorVersion

	err := checkCost(cost)
	if err != nil {
		return nil, err
	}
	p.cost = cost

	unencodedSalt := make([]byte, maxSaltSize)
	err = crypto.Random(unencodedSalt)
	if err != nil {
		return nil, err
	}

	p.salt = base64Encode(unencodedSalt)
	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}
	p.hash = hash
	return p, nil
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	if len(hashedSecret) < minHashSize {
		return nil, ErrHashTooShort
	}
	p := new(hashed)
	n, err := p.decodeVersion(hashedSecret)
	if err != nil {
		return nil, err
	}
	hashedSecret = hashedSecret[n:]
	n, err = p.decodeCost(hashedSecret)
	if err != nil {
		return nil, err
	}
	hashedSecret = hashedSecret[n:]

	p.salt = make([]byte, encodedSaltSize)
	copy(p.salt, hashedSecret[:encodedSaltSize])

	hashedSecret = hashedSecret[encodedSaltSize:]
	p.hash = make([]byte, len(hashedSecret))
	copy(p.hash, hashedSecret)

	return p, nil
}

func bcrypt(password []byte, cost int, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	hsh := base64Encode(cipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	csalt, err := base64Decode(salt)
	if err != nil {
		return nil, err
	}

	ckey := append(key[:len(key):len(key)], 0)

	c, err := blowfish.NewSaltedCipher(ckey, csalt)
	if err != nil {
		return nil, err
	}

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
}

func (p *hashed) Hash() []byte {
	arr := make([]byte, 60)
	arr[0] = '$'
	arr[1] = p.major
	n := 2
	if p.minor != 0 {
		arr[2] = p.minor
		n = 3
	}
	arr[n] = '$'
	n++
	costStr := Convert(p.cost).String()
	if len(costStr) == 1 {
		arr[n] = '0'
		arr[n+1] = costStr[0]
	} else {
		arr[n] = costStr[0]
		arr[n+1] = costStr[1]
	}
	n += 2
	arr[n] = '$'
	n++
	copy(arr[n:], p.salt)
	n += encodedSaltSize
	copy(arr[n:], p.hash)
	n += encodedHashSize
	return arr[:n]
}

func (p *hashed) decodeVersion(sbytes []byte) (int, error) {
	if sbytes[0] != '$' {
		return -1, Errf(ErrInvalidHashPrefix, sbytes[0])
	}
	if sbytes[1] > majorVersion {
		return -1, Errf(ErrHashVersionTooNew, sbytes[1])
	}
	p.major = sbytes[1]
	n := 3
	if sbytes[2] != '$' {
		p.minor = sbytes[2]
		n++
	}
	return n, nil
}

func (p *hashed) decodeCost(sbytes []byte) (int, error) {
	costVal, err := Convert(string(sbytes[0:2])).Int()
	if err != nil {
		return -1, err
	}
	err = checkCost(costVal)
	if err != nil {
		return -1, err
	}
	p.cost = costVal
	return 3, nil
}

func checkCost(cost int) error {
	if cost < MinCost {
		return Errf(ErrCostTooLow, cost, MinCost)
	}
	if cost > MaxCost {
		return Errf(ErrCostTooHigh, cost, MaxCost)
	}
	return nil
}
