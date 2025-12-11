# Symmetric Encryption

Symmetric encryption uses the same key for both encryption and decryption. This library uses AES-GCM, which is an authenticated encryption mode. This means that it not only encrypts the data but also provides a way to verify its integrity and authenticity.

## `Encrypt(plaintext, key []byte) ([]byte, error)`

Encrypts a plaintext using AES-GCM with a 32-byte key.

- **plaintext**: The data to encrypt.
- **key**: The 32-byte encryption key (AES-256).
- **Returns**: The ciphertext, which includes the nonce (a random number used once) and the encrypted data. Returns an error if the key is not 32 bytes long.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	key := make([]byte, 32) // In a real application, use a securely generated random key.
	plaintext := []byte("this is a secret message")

	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)
}
```

## `Decrypt(ciphertext, key []byte) ([]byte, error)`

Decrypts a ciphertext using AES-GCM with a 32-byte key.

- **ciphertext**: The data to decrypt. This should be the output of the `Encrypt` function.
- **key**: The 32-byte encryption key. Must be the same key used for encryption.
- **Returns**: The original plaintext. Returns an error if the key is not 32 bytes long, or if the ciphertext is corrupted or has been tampered with.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	key := make([]byte, 32) // Use the same key as for encryption.
	// ciphertext from the Encrypt example.
	ciphertext := ...

	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		panic(err) // This will happen if the key is wrong or the data is corrupt.
	}

	fmt.Printf("Plaintext: %s\n", plaintext)
}
```
