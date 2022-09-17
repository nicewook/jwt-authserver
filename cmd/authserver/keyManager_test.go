package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/ed25519"
)

func TestEd25519KeyGenerator(t *testing.T) {

	k, _ := Ed25519KeyGenerator()
	b, _ := json.MarshalIndent(k, "", "  ")
	t.Log(string(b))
}

func TestKeyManager(t *testing.T) {
	NewJWKCache()

	// first generate
	if err := keyManager(); err != nil {
		t.Error(err)
	}
	t.Logf("Key: %+v", Key)
	t.Log("JWKCache count:", JWKCache.ItemCount())

	// second generate
	if err := keyManager(); err != nil {
		t.Error(err)
	}
	t.Logf("Key: %+v", Key)
	t.Log("JWKCache count:", JWKCache.ItemCount())

	items := JWKCache.Items()
	for _, v := range items {
		t.Logf("exp time: %s", time.Unix(0, v.Expiration).Format(time.RFC3339))
	}

	b, _ := json.MarshalIndent(items, "", "  ")
	t.Log("items in cache:", string(b))

	// sign and verify
	token, err := CreateJWT(Key.privateKey)
	if err != nil {
		t.Error(err)
	}

	pub, err := base64.RawURLEncoding.DecodeString(Key.X)
	if err != nil {
		t.Error(err)
	}
	pub2 := ed25519.PublicKey(pub)
	publicKey := crypto.PublicKey(pub2)
	t.Logf("publicKey: %x", publicKey)

	// jwt package specific part of verification
	parts := strings.Split(token, ".")

	method := jwt.GetSigningMethod(Key.Alg)

	if err = method.Verify(strings.Join(parts[0:2], "."), parts[2], publicKey); err != nil {
		t.Errorf("err: %v", err)
	}

	t.Log("VERIFIED!")
}
