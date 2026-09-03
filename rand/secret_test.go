package rand_test

import (
	"strings"
	"testing"

	"github.com/tinywasm/base64"
	"github.com/tinywasm/crypto/rand"
)

func TestSecretIsURLSafe(t *testing.T) {
	sec, err := rand.Secret()
	if err != nil {
		t.Fatalf("Secret() failed: %v", err)
	}

	if strings.ContainsAny(sec, "+/=") {
		t.Errorf("Secret contains non-URL-safe characters: %s", sec)
	}

	decoded, err := base64.URLDecode(sec)
	if err != nil {
		t.Fatalf("base64.URLDecode failed: %v", err)
	}

	if len(decoded) != rand.DefaultSecretBytes {
		t.Errorf("expected decoded length %d, got %d", rand.DefaultSecretBytes, len(decoded))
	}
}

func TestSecretUnique(t *testing.T) {
	const count = 100
	secrets := make([]string, 0, count)

	for i := 0; i < count; i++ {
		sec, err := rand.Secret()
		if err != nil {
			t.Fatalf("Secret() failed on iteration %d: %v", i, err)
		}
		for _, prev := range secrets {
			if prev == sec {
				t.Fatalf("duplicate secret detected: %s", sec)
			}
		}
		secrets = append(secrets, sec)
	}
}

func TestSecretNDefaultsOnNonPositive(t *testing.T) {
	secDefault, errDef := rand.Secret()
	if errDef != nil {
		t.Fatalf("Secret() failed: %v", errDef)
	}

	sec0, err0 := rand.SecretN(0)
	if err0 != nil {
		t.Fatalf("SecretN(0) failed: %v", err0)
	}

	secNeg, errNeg := rand.SecretN(-5)
	if errNeg != nil {
		t.Fatalf("SecretN(-5) failed: %v", errNeg)
	}

	if len(sec0) != len(secDefault) {
		t.Errorf("expected SecretN(0) length %d, got %d", len(secDefault), len(sec0))
	}

	if len(secNeg) != len(secDefault) {
		t.Errorf("expected SecretN(-5) length %d, got %d", len(secDefault), len(secNeg))
	}
}

func TestSecret_ShapedLikeASessionToken(t *testing.T) {
	const count = 1000
	tokens := make([]string, 0, count)

	for i := 0; i < count; i++ {
		token, err := rand.Secret()
		if err != nil {
			t.Fatalf("Secret() failed on iteration %d: %v", i, err)
		}

		for _, prev := range tokens {
			if prev == token {
				t.Fatalf("duplicate token detected at iteration %d: %s", i, token)
			}
			if strings.HasPrefix(token, prev) || strings.HasPrefix(prev, token) {
				t.Fatalf("prefix collision detected between %s and %s", token, prev)
			}
		}

		tokens = append(tokens, token)
	}
}
