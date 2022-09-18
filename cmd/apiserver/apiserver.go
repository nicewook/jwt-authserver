package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/patrickmn/go-cache"
)

const JWKSServerURL = "https://localhost/jwks"

type EdDSAKey struct {
	Kty        string             `json:"kty,omitempty"`
	Kid        string             `json:"kid,omitempty"`
	Alg        string             `json:"alg,omitempty"`
	Crv        string             `json:"crv,omitempty"`
	X          string             `json:"x,omitempty"` // base64 encoded public key
	Use        string             `json:"use,omitempty"`
	privateKey ed25519.PrivateKey // it will not be marshaled
	Exp        int64              `json:"exp,omitempty"`
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

var jwks map[string]EdDSAKey

func GetJWKS() {
	// InsecureSkipVerify: true  ## thats what you need
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := c.Get(JWKSServerURL)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var jwks map[string]EdDSAKey
	if err := json.Unmarshal(body, &jwks); err != nil {
		log.Fatal(err)
	}
	b, err := json.MarshalIndent(jwks, "", " ")
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("count jwks: %v", len(jwks))
	log.Printf("jwks: %v", string(b))

	// caching
	JWKCache.Flush()
	for k, v := range jwks {
		JWKCache.SetDefault(k, v)
	}
}

type jwtCustomClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func getPublicKey(kid string) ([]byte, error) {
	log.Println(JWKCache.Items())
	val, exist := JWKCache.Get(kid)
	if !exist {
		return nil, fmt.Errorf("KeyID not exist")
	}

	key, ok := val.(EdDSAKey)
	if !ok {
		return nil, fmt.Errorf("not EdDSA Key in cache")
	}
	return base64.RawURLEncoding.DecodeString(key.X)
}

func JWTChecker(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		log.Println("jwt checker")
		raw := c.Request().Header.Get("Authorization")
		auth := strings.Split(raw, " ")
		log.Println(auth)
		if auth[0] != "Bearer" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"message": "wrong Authentication header",
			})
		}
		log.Println(auth[1]) // it is raw token

		// token parse
		token, err := jwt.ParseWithClaims(auth[1], &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("AllYourBase"), nil
		})

		claims, ok := token.Claims.(*jwtCustomClaims)
		if ok && token.Valid {
			log.Printf("%v", claims.StandardClaims.Issuer)
		} else {
			log.Println("err:", err)
		}
		log.Printf("%v", claims.StandardClaims.Issuer)
		log.Printf("kid: %v", token.Header["kid"])

		kid := token.Header["kid"]

		pub, err := getPublicKey(kid.(string))
		if err != nil {
			log.Println(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "fail to get key",
			})
		}
		pub2 := ed25519.PublicKey(pub)
		publicKey := crypto.PublicKey(pub2)

		// jwt package specific part of verification
		parts := strings.Split(token.Raw, ".")
		method := jwt.GetSigningMethod("EdDSA")
		if err = method.Verify(strings.Join(parts[0:2], "."), parts[2], publicKey); err != nil {
			log.Printf("err: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"message": "fail to get key",
			})
		}

		log.Println("VERIFIED!")

		return next(c)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("start")
	go func() {
		for {
			GetJWKS()
			time.Sleep(10 * time.Minute)
		}
	}()

	e := echo.New()

	// middleware
	e.Use(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{Limit: "15G"}))

	e.GET("/", Hello)

	// handler
	api := e.Group("/api")
	{
		api.Use(JWTChecker)
		api.GET("/hello", HelloJWT)
	}

	e.Logger.Fatal(e.StartTLS(":8443", "server.crt", "server.key"))
}

func init() {
	// go GetJWKS()
	NewJWKCache()
}
