package auth_jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type jwtClaims struct {
	Data string
	jwt.StandardClaims
}

type AuthJWT struct {
	SecretKey         string
	TokenDuration     time.Duration
	invalidatedTokens map[string]time.Time
}

func ApiMiddleware(name string, j *AuthJWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(name, j)
		c.Next()
	}
}

func (x *AuthJWT) GenerateJWT(data string) string {
	var mySigningKey = []byte(x.SecretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := &jwtClaims{}

	claims.Data = data
	claims.ExpiresAt = time.Now().Add(x.TokenDuration).Unix()
	token.Claims = claims
	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return ""
	}
	return tokenString
}

func (x *AuthJWT) IsAuthorized(r *http.Request) (string, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return "", false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(parts[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return "", false
	}

	_ = token
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {

		if x.invalidatedTokens == nil {
			x.invalidatedTokens = make(map[string]time.Time)
		}

		_, ok := x.invalidatedTokens[parts[1]]

		for key, val := range x.invalidatedTokens {
			if time.Now().After(val) {
				delete(x.invalidatedTokens, key)
			}
		}

		if !ok {
			tm := time.Unix(claims.ExpiresAt, 0)
			if time.Now().UTC().After(tm) {
				return "", false
			}
			return claims.Data, true
		}
		return "", false
	} else {
		return "", false
	}
}

func (x *AuthJWT) IsAuthorizedWithKey(r *http.Request, key string) (string, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return "", false
	}

	var mySigningKey = []byte(key)
	token, err := jwt.ParseWithClaims(parts[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})
	if err != nil {
		return "", false
	}

	_ = token
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {

		if x.invalidatedTokens == nil {
			x.invalidatedTokens = make(map[string]time.Time)
		}

		_, ok := x.invalidatedTokens[parts[1]]
		for key, val := range x.invalidatedTokens {
			if time.Now().After(val) {
				delete(x.invalidatedTokens, key)
			}
		}
		if !ok {

			tm := time.Unix(claims.ExpiresAt, 0)
			if time.Now().UTC().After(tm) {
				return "", false
			}
			return claims.Data, true
		}
		return "", false

	} else {
		return "", false
	}
}

func (x *AuthJWT) InvalidateJWT(r *http.Request) bool {

	for key, val := range x.invalidatedTokens {
		if time.Now().After(val) {
			delete(x.invalidatedTokens, key)
		}
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(parts[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return false
	}

	_ = token
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {

		if x.invalidatedTokens == nil {
			x.invalidatedTokens = make(map[string]time.Time)
		}

		_, ok := x.invalidatedTokens[parts[1]]
		if ok {
			return false
		}
		x.invalidatedTokens[parts[1]] = time.Unix(claims.ExpiresAt, 0)
	}

	return true
}
