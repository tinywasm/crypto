# Digital Signatures

Digital signatures are used to verify the authenticity and integrity of a message. They are created with a private key and verified with a public key. If a signature is successfully verified with a public key, it proves that the message was signed by the holder of the corresponding private key and that the message has not been tampered with.

This library uses ECDSA (Elliptic Curve Digital Signature Algorithm) with the P-256 curve and SHA-256 for hashing.

## `Sign(message, privateKey []byte) ([]byte, error)`

Creates a digital signature for a message using a private key.

- **message**: The message to sign. The function will first calculate the SHA-256 hash of this message.
- **privateKey**: The private key to use for signing.
- **Returns**: The signature and an error if any. Returns an error if the private key is invalid.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	// Assume you have a private key.
	myPrivateKey := ...
	message := []byte("this message needs to be signed")

	signature, err := crypto.Sign(message, myPrivateKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signature: %x\n", signature)
}
```

## `Verify(message, signature, publicKey []byte) (bool, error)`

Verifies a digital signature of a message using a public key.

- **message**: The message that was signed.
- **signature**: The signature to verify.
- **publicKey**: The public key to use for verification.
- **Returns**: `true` if the signature is valid, `false` otherwise. Returns an error if the public key is invalid.

### Example

```go
package main

import (
	"fmt"
	"github.com/tinywasm/crypto"
)

func main() {
	crypto := tinycrypto.New()

	// Assume you have the public key, the message, and the signature.
	publicKey := ...
	message := []byte("this message needs to be signed")
	signature := ...

	ok, err := crypto.Verify(message, signature, publicKey)
	if err != nil {
		panic(err)
	}

	if ok {
		fmt.Println("Signature is valid!")
	} else {
		fmt.Println("Signature is NOT valid!")
	}
}
```
