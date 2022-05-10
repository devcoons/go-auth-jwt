package auth_jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type AuthJWT struct {
	SecretKey string
	TokenDuration time.Duration
}

func ApiMiddleware(j AuthJWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("middleware_auth", j)
		c.Next()
	}
}

func (x AuthJWT) GenerateJWT(email string, role string,) string {
	var mySigningKey = []byte(x.SecretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(x.TokenDuration).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return ""
	}
	return tokenString
}

func (x AuthJWT) IsAuthorized(r *http.Request) bool {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})
	_ = token

	return err == nil
}
