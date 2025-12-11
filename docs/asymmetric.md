# Asymmetric Encryption

Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption. This allows anyone to encrypt a message for a recipient, but only the recipient with the private key can decrypt it.

This library uses ECIES (Elliptic Curve Integrated Encryption Scheme), which combines ECDH (Elliptic Curve Diffie-Hellman) for key agreement with AES-GCM for data encryption.

## `GenerateKeyPair() ([]byte, []byte, error)`

Generates a new key pair for asymmetric cryptography. The keys are based on the P-256 elliptic curve.

- **Returns**: The public key, the private key, and an error if any. The keys are returned as byte slices in standard formats (PKIX for public keys, SEC1 for private keys).

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	publicKey, privateKey, err := crypto.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Public Key: %x\n", publicKey)
	fmt.Printf("Private Key: %x\n", privateKey)
}
```

## `EncryptAsymmetric(plaintext, publicKey []byte) ([]byte, error)`

Encrypts a plaintext using the recipient's public key.

- **plaintext**: The data to encrypt.
- **publicKey**: The recipient's public key.
- **Returns**: The ciphertext. This ciphertext includes an ephemeral public key that the recipient needs to decrypt the message. Returns an error if the public key is invalid.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	// Assume you have the recipient's public key.
	recipientPublicKey := ...
	plaintext := []byte("this is a secret message for the recipient")

	ciphertext, err := crypto.EncryptAsymmetric(plaintext, recipientPublicKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Asymmetric Ciphertext: %x\n", ciphertext)
}
```

## `DecryptAsymmetric(ciphertext, privateKey []byte) ([]byte, error)`

Decrypts a ciphertext using the recipient's private key.

- **ciphertext**: The data to decrypt. This should be the output of the `EncryptAsymmetric` function.
- **privateKey**: The recipient's private key.
- **Returns**: The original plaintext. Returns an error if the private key is invalid or if the ciphertext is corrupted.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	// Assume you have your private key and the ciphertext.
	myPrivateKey := ...
	ciphertext := ...

	plaintext, err := crypto.DecryptAsymmetric(ciphertext, myPrivateKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Asymmetric Plaintext: %s\n", plaintext)
}
```
