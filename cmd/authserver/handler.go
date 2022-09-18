package main

import (
	"fmt"
	"jwt-authserver/internal/secret"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

type User struct {
	Username string
	Password string
	Role     string
}
type respMsg map[string]string

var userMap map[string]User

func Hello(c echo.Context) error {
	log.Println("hello")
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Hello, I am Authentication server",
	})
}

func SignIn(c echo.Context) error {
	log.Println("sign in")

	var user User
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, respMsg{
			"message": err.Error(),
		})
	}
	log.Println("log in attempt:", user.Username, user.Password)

	foundUser, ok := userMap[user.Username]
	if !ok {
		return c.JSON(http.StatusUnauthorized, respMsg{
			"message": fmt.Sprintf("not exist user: %v", user.Username),
		})
	}

	matched, err := secret.CheckPasswordAndHash(user.Password, foundUser.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, respMsg{
			"message": "matching process failure",
		})
	}
	if !matched {
		return c.JSON(http.StatusOK, respMsg{
			"message": "not matched",
		})
	}

	// generate JWT
	token, err := CreateJWT(Key.privateKey, foundUser)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, respMsg{
			"message": "creating JWT failure",
		})
	}

	return c.JSON(http.StatusOK, respMsg{
		"accessToken": token,
	})
}

func GetJWKS(c echo.Context) error {
	log.Println("get jwks")

	// b, err := json.Marshal(JWKCache.Items())
	// log.Println(err)
	// if err != nil {
	// 	log.Println(err)
	// 	return c.JSON(http.StatusInternalServerError, respMsg{
	// 		"message": err.Error(),
	// 	})
	// }
	return c.JSON(http.StatusOK, JWKCache.Items())
}

func init() {
	userMap = make(map[string]User, 10)

	hashedPassword, _ := secret.HashPassword("1234")
	userMap["admin"] = User{
		Username: "admin",
		Password: hashedPassword,
		Role:     "admin",
	}
}
