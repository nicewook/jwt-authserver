package main

import (
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4/middleware"
	"github.com/patrickmn/go-cache"
)

// https://curity.io/resources/learn/jwt-signatures/#eddsa-jwk-encoding
// https://www.rfc-editor.org/rfc/rfc8037.html#section-2
// The parameter "x" MUST be present and contain the public key
// encoded using the base64url [RFC4648] encoding.
type EdDSAKey struct {
	Kty        string             `json:"kty,omitempty"`
	Kid        string             `json:"kid,omitempty"`
	Alg        string             `json:"alg,omitempty"`
	Crv        string             `json:"crv",omitempty`
	X          string             `json:"x,omitempty"` // base64 encoded public key
	Use        string             `json:"sig,omitempty"`
	privateKey ed25519.PrivateKey // it will not be marshaled
	Exp        int64              `json:"exp,omitempty"`
}

func NewEdDSAKey() EdDSAKey {
	return EdDSAKey{
		Kty: "OKP",
		Alg: "EdDSA",
		Use: "sig",
	}
}

func Ed25519KeyGenerator() (EdDSAKey, error) {

	var key EdDSAKey
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return key, err
	}

	// https://curity.io/resources/learn/jwt-signatures/
	key = NewEdDSAKey()
	key.Kid = md5Hash(pub)
	key.X = base64.RawURLEncoding.EncodeToString(pub)
	key.privateKey = priv
	key.Exp = time.Now().Add(jwkGenInterval + jwtExpireDuation).Unix()
	return key, nil
}

func md5Hash(b []byte) string {
	hash := md5.Sum(b)
	return hex.EncodeToString(hash[:])
}

const (
	jwkGenInterval   = 10 * time.Minute
	jwtExpireDuation = 10 * time.Minute
)

var (
	Key      EdDSAKey
	JWKCache *cache.Cache
)

func NewJWKCache() {
	JWKCache = cache.New(
		jwkGenInterval+jwtExpireDuation,
		jwkGenInterval+jwtExpireDuation,
	)
}

func keyManager() error {
	var err error
	Key, err = Ed25519KeyGenerator()
	if err != nil {
		return err
	}

	JWKCache.SetDefault(Key.Kid, Key)
	return err
}

type jwtCustomClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func JWTConfig(publicKey []byte) middleware.JWTConfig {
	return middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: publicKey,
	}
}

func CreateJWT(privateKey ed25519.PrivateKey) (string, error) {

	log.Printf("privateKey Type %T", privateKey)
	// Set custom claims
	claims := &jwtCustomClaims{
		Username: "user1",
		Role:     "administrator",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(jwtExpireDuation).Unix(),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	// Generate encoded token and send it as response.
	// test
	return token.SignedString(privateKey)
}
