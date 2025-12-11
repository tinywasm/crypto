package main

import (
	"syscall/js"

	"github.com/tinywasm/crypto"
)

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("tinycrypto", js.ValueOf(map[string]interface{}{
		"encrypt":           js.FuncOf(encrypt),
		"decrypt":           js.FuncOf(decrypt),
		"generateKeyPair":   js.FuncOf(generateKeyPair),
		"encryptAsymmetric": js.FuncOf(encryptAsymmetric),
		"decryptAsymmetric": js.FuncOf(decryptAsymmetric),
		"sign":              js.FuncOf(sign),
		"verify":            js.FuncOf(verify),
	}))
	<-c
}

var engine = tinycrypto.New()

func encrypt(this js.Value, args []js.Value) interface{} {
	plaintext := jsValueToBytes(args[0])
	key := jsValueToBytes(args[1])
	ciphertext, err := engine.Encrypt(plaintext, key)
	return bytesToJsValue(ciphertext, err)
}

func decrypt(this js.Value, args []js.Value) interface{} {
	ciphertext := jsValueToBytes(args[0])
	key := jsValueToBytes(args[1])
	plaintext, err := engine.Decrypt(ciphertext, key)
	return bytesToJsValue(plaintext, err)
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	pub, priv, err := engine.GenerateKeyPair()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	return js.ValueOf(map[string]interface{}{
		"publicKey":  bytesToUint8Array(pub),
		"privateKey": bytesToUint8Array(priv),
	})
}

func encryptAsymmetric(this js.Value, args []js.Value) interface{} {
	plaintext := jsValueToBytes(args[0])
	publicKey := jsValueToBytes(args[1])
	ciphertext, err := engine.EncryptAsymmetric(plaintext, publicKey)
	return bytesToJsValue(ciphertext, err)
}

func decryptAsymmetric(this js.Value, args []js.Value) interface{} {
	ciphertext := jsValueToBytes(args[0])
	privateKey := jsValueToBytes(args[1])
	plaintext, err := engine.DecryptAsymmetric(ciphertext, privateKey)
	return bytesToJsValue(plaintext, err)
}

func sign(this js.Value, args []js.Value) interface{} {
	message := jsValueToBytes(args[0])
	privateKey := jsValueToBytes(args[1])
	signature, err := engine.Sign(message, privateKey)
	return bytesToJsValue(signature, err)
}

func verify(this js.Value, args []js.Value) interface{} {
	message := jsValueToBytes(args[0])
	signature := jsValueToBytes(args[1])
	publicKey := jsValueToBytes(args[2])
	ok, err := engine.Verify(message, signature, publicKey)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	return js.ValueOf(map[string]interface{}{"ok": ok})
}

func jsValueToBytes(val js.Value) []byte {
	b := make([]byte, val.Get("length").Int())
	js.CopyBytesToGo(b, val)
	return b
}

func bytesToUint8Array(b []byte) js.Value {
	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(uint8Array, b)
	return uint8Array
}

func bytesToJsValue(b []byte, err error) interface{} {
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	return js.ValueOf(map[string]interface{}{"value": bytesToUint8Array(b)})
}
