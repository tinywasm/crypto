package crypto

import (
	"log"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/require"
)

func isTinyGoInstalled() bool {
	_, err := exec.LookPath("tinygo")
	return err == nil
}

func withPage(t *testing.T, f func(page playwright.Page)) {
	// Compile the wasm module
	var cmd *exec.Cmd
	if isTinyGoInstalled() {
		cmd = exec.Command("tinygo", "build", "-o", "testdata/main.wasm", "-target", "wasm", "./cmd")
	} else {
		cmd = exec.Command("go", "build", "-o", "testdata/main.wasm", "./cmd")
		cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile wasm: %v", err)
	}

	// Start a web server
	server := &http.Server{Addr: ":8080", Handler: http.FileServer(http.Dir("testdata"))}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()
	defer server.Close()

	// Run playwright
	pw, err := playwright.Run()
	require.NoError(t, err)
	defer func() { require.NoError(t, pw.Stop()) }()

	browser, err := pw.Chromium.Launch()
	require.NoError(t, err)
	defer func() { require.NoError(t, browser.Close()) }()

	page, err := browser.NewPage()
	require.NoError(t, err)

	page.On("console", func(msg playwright.ConsoleMessage) {
		t.Log("Console:", msg.Text())
	})

	_, err = page.Goto("http://localhost:8080")
	require.NoError(t, err)

	// Wait for the wasm module to be loaded
	_, err = page.WaitForFunction("() => window.tinycrypto", nil)
	require.NoError(t, err)

	f(page)
}

func TestPlaywrightEncryptDecrypt(t *testing.T) {
	withPage(t, func(page playwright.Page) {
		plaintext := "hello wasm"
		key := make([]byte, 32)

		result, err := page.Evaluate("async ({ plaintext, key }) => await window.tinycrypto.encrypt(new TextEncoder().encode(plaintext), new Uint8Array(key))", map[string]interface{}{
			"plaintext": plaintext,
			"key":       key,
		})
		require.NoError(t, err)
		ciphertext := result.(map[string]interface{})["value"].([]float64)

		result, err = page.Evaluate("async ({ ciphertext, key }) => await window.tinycrypto.decrypt(new Uint8Array(ciphertext), new Uint8Array(key))", map[string]interface{}{
			"ciphertext": ciphertext,
			"key":        key,
		})
		require.NoError(t, err)
		decryptedBytes := result.(map[string]interface{})["value"].([]float64)
		decrypted := bytesToString(decryptedBytes)

		require.Equal(t, plaintext, decrypted)
	})
}

func TestPlaywrightSignVerify(t *testing.T) {
	withPage(t, func(page playwright.Page) {
		// Generate key pair
		result, err := page.Evaluate("async () => await window.tinycrypto.generateKeyPair()")
		require.NoError(t, err)
		keyPair := result.(map[string]interface{})
		pub := keyPair["publicKey"].([]float64)
		priv := keyPair["privateKey"].([]float64)

		// Sign
		message := "this is a test message"
		result, err = page.Evaluate("async ({ message, priv }) => await window.tinycrypto.sign(new TextEncoder().encode(message), new Uint8Array(priv))", map[string]interface{}{
			"message": message,
			"priv":    priv,
		})
		require.NoError(t, err)
		signature := result.(map[string]interface{})["value"].([]float64)

		// Verify
		result, err = page.Evaluate("async ({ message, signature, pub }) => await window.tinycrypto.verify(new TextEncoder().encode(message), new Uint8Array(signature), new Uint8Array(pub))", map[string]interface{}{
			"message":   message,
			"signature": signature,
			"pub":       pub,
		})
		require.NoError(t, err)
		ok := result.(map[string]interface{})["ok"].(bool)
		require.True(t, ok)
	})
}

func TestPlaywrightEncryptDecryptAsymmetric(t *testing.T) {
	withPage(t, func(page playwright.Page) {
		// Generate key pair
		result, err := page.Evaluate("async () => await window.tinycrypto.generateKeyPair()")
		require.NoError(t, err)
		keyPair := result.(map[string]interface{})
		pub := keyPair["publicKey"].([]float64)
		priv := keyPair["privateKey"].([]float64)

		// Encrypt
		plaintext := "hello asymmetric wasm"
		result, err = page.Evaluate("async ({ plaintext, pub }) => await window.tinycrypto.encryptAsymmetric(new TextEncoder().encode(plaintext), new Uint8Array(pub))", map[string]interface{}{
			"plaintext": plaintext,
			"pub":       pub,
		})
		require.NoError(t, err)
		ciphertext := result.(map[string]interface{})["value"].([]float64)

		// Decrypt
		result, err = page.Evaluate("async ({ ciphertext, priv }) => await window.tinycrypto.decryptAsymmetric(new Uint8Array(ciphertext), new Uint8Array(priv))", map[string]interface{}{
			"ciphertext": ciphertext,
			"priv":       priv,
		})
		require.NoError(t, err)
		decryptedBytes := result.(map[string]interface{})["value"].([]float64)
		decrypted := bytesToString(decryptedBytes)

		require.Equal(t, plaintext, decrypted)
	})
}

func bytesToString(bytes []float64) string {
	b := make([]byte, len(bytes))
	for i, v := range bytes {
		b[i] = byte(v)
	}
	return string(b)
}
