package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
)

// type User struct {
// 	Username string
// 	Password string
// 	Role     string
// }
// type respMsg map[string]string

// var userMap map[string]User

func Hello(c echo.Context) error {
	log.Println("hello")
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Hello, I am API server",
	})
}

// func SignIn(c echo.Context) error {
// 	log.Println("sign in")

// 	var user User
// 	if err := c.Bind(&user); err != nil {
// 		return c.JSON(http.StatusBadRequest, respMsg{
// 			"message": err.Error(),
// 		})
// 	}
// 	log.Println("log in attempt:", user.Username, user.Password)

// 	foundUser, ok := userMap[user.Username]
// 	if !ok {
// 		c.JSON(http.StatusOK, respMsg{
// 			"message": fmt.Sprintf("not exist user: %v", user.Username),
// 		})
// 	}

// 	matched, err := secret.CheckPasswordAndHash(user.Password, foundUser.Password)
// 	if err != nil {
// 		return c.JSON(http.StatusInternalServerError, respMsg{
// 			"message": "matching process failure",
// 		})
// 	}
// 	if !matched {
// 		return c.JSON(http.StatusOK, respMsg{
// 			"message": "not matched",
// 		})
// 	}

// 	// generate JWT

// 	return c.JSON(http.StatusOK, respMsg{})
// }

// func GetJWKS(c echo.Context) error {
// 	log.Println("get jwks")

// 	b, err := json.Marshal(JWKCache.Items())
// 	log.Println(err)
// 	if err != nil {
// 		log.Println(err)
// 		return c.JSON(http.StatusInternalServerError, respMsg{
// 			"message": err.Error(),
// 		})
// 	}
// 	return c.JSON(http.StatusOK, respMsg{
// 		"keys": string(b),
// 	})
// }
