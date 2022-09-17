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
		c.JSON(http.StatusOK, respMsg{
			"message": fmt.Sprintf("not exist user: %v", user.Username),
		})
	}

	matched, err := secret.CheckPasswordAndHash(user.Password, foundUser.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, respMsg{
			"message": "matching process failure",
		})
	}
	if !matched {
		c.JSON(http.StatusOK, respMsg{
			"message": "not matched",
		})
	}

	// generate JWT

	return c.JSON(http.StatusOK, respMsg{})
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
