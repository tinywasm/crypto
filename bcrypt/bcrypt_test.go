package bcrypt_test

import (
	"bytes"

	"testing"

	xbcrypt "golang.org/x/crypto/bcrypt"

	"github.com/tinywasm/crypto/bcrypt"
)

func TestBcryptingIsEasy(t *testing.T) {
	pass := []byte("mypassword")
	hp, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword error: %s", err)
	}

	if bcrypt.CompareHashAndPassword(hp, pass) != nil {
		t.Errorf("%v should hash %s correctly", hp, pass)
	}

	notPass := "notthepass"
	err = bcrypt.CompareHashAndPassword(hp, []byte(notPass))
	if err != bcrypt.ErrMismatchedHashAndPassword {
		t.Errorf("%v and %s should be mismatched", hp, notPass)
	}
}

func TestBcryptingIsCorrect(t *testing.T) {
	pass := []byte("allmine")
	expectedHash := []byte("$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga")

	err := bcrypt.CompareHashAndPassword(expectedHash, pass)
	if err != nil {
		t.Fatalf("CompareHashAndPassword failed for known vector: %v", err)
	}
}

func TestInteropWithXCrypto(t *testing.T) {
	pass := []byte("interop-password")
	xHash, err := xbcrypt.GenerateFromPassword(pass, xbcrypt.MinCost)
	if err != nil {
		t.Fatalf("x/crypto GenerateFromPassword error: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(xHash, pass)
	if err != nil {
		t.Errorf("CompareHashAndPassword failed for x/crypto generated hash: %v", err)
	}

	ourHash, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("our GenerateFromPassword error: %v", err)
	}

	err = xbcrypt.CompareHashAndPassword(ourHash, pass)
	if err != nil {
		t.Errorf("x/crypto CompareHashAndPassword failed for our generated hash: %v", err)
	}
}

func TestWrongPasswordSentinel(t *testing.T) {
	pass := []byte("correctpassword")
	wrong := []byte("wrongpassword")

	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword error: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(hash, wrong)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if err != bcrypt.ErrMismatchedHashAndPassword {
		t.Errorf("expected ErrMismatchedHashAndPassword, got %v", err)
	}
}

func TestCostValidation(t *testing.T) {
	pass := []byte("password")

	_, err := bcrypt.GenerateFromPassword(pass, 3)
	if err != nil {
		t.Errorf("cost 3 should default to DefaultCost in GenerateFromPassword, got err: %v", err)
	}

	_, err = bcrypt.GenerateFromPassword(pass, 32)
	if err == nil {
		t.Errorf("cost 32 should fail")
	}

	costHash := []byte("$2a$12$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga")
	c, err := bcrypt.Cost(costHash)
	if err != nil {
		t.Fatalf("Cost error: %v", err)
	}
	if c != 12 {
		t.Errorf("Cost returned %d, want 12", c)
	}
}

func TestPasswordTooLong(t *testing.T) {
	longPass := make([]byte, 73)
	for i := range longPass {
		longPass[i] = 'a'
	}

	_, err := bcrypt.GenerateFromPassword(longPass, bcrypt.MinCost)
	if err != bcrypt.ErrPasswordTooLong {
		t.Errorf("expected ErrPasswordTooLong, got %v", err)
	}
}

func TestUniqueSaltPerHash(t *testing.T) {
	pass := []byte("samepassword")
	h1, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword h1 error: %v", err)
	}
	h2, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword h2 error: %v", err)
	}

	if bytes.Equal(h1, h2) {
		t.Errorf("hashes for same password should be different due to random salt, got %s and %s", h1, h2)
	}
}

func TestInvalidHashErrors(t *testing.T) {
	invalidHashes := [][]byte{
		[]byte("$2a$10$fooo"),
		[]byte("$2a"),
	}

	for _, ih := range invalidHashes {
		err := bcrypt.CompareHashAndPassword(ih, []byte("anything"))
		if err != bcrypt.ErrHashTooShort {
			t.Errorf("for hash %q expected ErrHashTooShort, got %v", ih, err)
		}
	}
}
