package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/patrickmn/go-cache"
)

const JWKSServerURL = "https://localhost/jwks"

var JWKS map[string]cache.Item

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
	if err := json.Unmarshal(body, &JWKS); err != nil {
		log.Fatal(err)
	}
	log.Printf("count jwks: %v", len(JWKS))

}
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("start")
	go func() {
		for {
			GetJWKS()
			time.Sleep(10 * time.Second)
		}
	}()

	e := echo.New()

	// middleware
	e.Use(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{Limit: "15G"}))

	// handler
	e.GET("/", Hello)

	e.Logger.Fatal(e.StartTLS(":8443", "server.crt", "server.key"))
}

func init() {
	// go GetJWKS()
}
