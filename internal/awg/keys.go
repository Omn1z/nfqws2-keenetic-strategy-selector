package awg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenKeypair returns a base64 (std) WireGuard X25519 keypair. The private key is
// clamped before encoding, matching `wg genkey`'s stored form.
func GenKeypair() (priv string, pub string, err error) {
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	pubB, err := curve25519.X25519(b[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), base64.StdEncoding.EncodeToString(pubB), nil
}

// PubFromPriv derives the base64 public key from a base64 private key.
func PubFromPriv(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return "", fmt.Errorf("некорректный приватный ключ: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("приватный ключ должен быть 32 байта")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GenPSK returns a base64 32-byte preshared key.
func GenPSK() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}
