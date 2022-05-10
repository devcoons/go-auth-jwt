package auth_jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type userClaims struct {
	Email      string `json:"email"`
	Authorized bool   `json:"authorized"`
	Role       string `json:"role"`

	jwt.StandardClaims
}

type AuthJWT struct {
	SecretKey     string
	TokenDuration time.Duration
}

func ApiMiddleware(j AuthJWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("middleware_auth", j)
		c.Next()
	}
}

func (x AuthJWT) GenerateJWT(email string, role string) string {
	var mySigningKey = []byte(x.SecretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := &userClaims{}

	claims.Email = email
	claims.Authorized = true
	claims.Role = role
	claims.ExpiresAt = time.Now().Add(x.TokenDuration).Unix()

	token.Claims = claims

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return ""
	}
	return tokenString
}

func (x AuthJWT) IsAuthorized(r *http.Request) (string, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return "", false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(parts[1], &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return "", false
	}

	_ = token
	if claims, ok := token.Claims.(*userClaims); ok && token.Valid {
		return claims.Email, true

	} else {
		return "", false
	}

}
