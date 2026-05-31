package auth

import (
	"testing"

	"github.com/GehirnInc/crypt"
)

func TestVerifyHashRoundTrip(t *testing.T) {
	algos := map[string]crypt.Crypt{"md5": crypt.MD5, "sha256": crypt.SHA256, "sha512": crypt.SHA512}
	for name, algo := range algos {
		c := crypt.New(algo)
		h, err := c.Generate([]byte("test123"), nil)
		if err != nil {
			t.Fatalf("%s generate: %v", name, err)
		}
		if !verifyHash("test123", h) {
			t.Errorf("%s: correct password rejected (hash=%s)", name, h)
		}
		if verifyHash("wrong", h) {
			t.Errorf("%s: wrong password accepted (hash=%s)", name, h)
		}
	}
}
