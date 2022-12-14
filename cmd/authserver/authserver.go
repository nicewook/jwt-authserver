package main

import (
	"log"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("start")

	e := echo.New()

	// middleware
	e.Use(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{Limit: "15G"}))

	// handler
	e.GET("/", Hello)
	e.POST("/signin", SignIn)
	e.GET("/jwks", GetJWKS)

	e.Logger.Fatal(e.StartTLS(":443", "server.crt", "server.key"))
}

func init() {
	NewJWKCache()

	go func() {
		for {
			if err := keyManager(); err != nil {
				log.Println(err)
			}
			time.Sleep((10 * time.Minute))
		}
	}()

}
