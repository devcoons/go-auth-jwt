package auth_jwt

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

type userClaims struct {
	UserId     int    `json:"userId"`
	Username   string `json:"username"`
	Authorized bool   `json:"authorized"`
	Role       string `json:"role"`
	jwt.StandardClaims
}

type AuthJWT struct {
	SecretKey         string
	TokenDuration     time.Duration
	invalidatedTokens map[string]time.Time
}

func ApiMiddleware(j *AuthJWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("middleware_auth", j)
		c.Next()
	}
}

func (x *AuthJWT) GenerateJWT(userId int, username string, authorized bool, role string) string {
	var mySigningKey = []byte(x.SecretKey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := &userClaims{}

	claims.UserId = userId
	claims.Username = username
	claims.Authorized = authorized
	claims.Role = role
	claims.ExpiresAt = time.Now().Add(x.TokenDuration).Unix()

	token.Claims = claims

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		return ""
	}
	return tokenString
}

func (x *AuthJWT) IsAuthorized(r *http.Request) ([]string, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return nil, false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(parts[1], &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return nil, false
	}

	_ = token
	if claims, ok := token.Claims.(*userClaims); ok && token.Valid {

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
			return []string{strconv.Itoa(claims.UserId), claims.Username, strconv.FormatBool(claims.Authorized), claims.Role}, true
		}

		return nil, false

	} else {
		return nil, false
	}

}

func (x *AuthJWT) IsAuthorizedWithKey(r *http.Request, key string) ([]string, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return nil, false
	}

	var mySigningKey = []byte(key)
	token, err := jwt.ParseWithClaims(parts[1], &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})
	if err != nil {
		return nil, false
	}

	_ = token
	if claims, ok := token.Claims.(*userClaims); ok && token.Valid {

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
			return []string{strconv.Itoa(claims.UserId), claims.Username, strconv.FormatBool(claims.Authorized), claims.Role}, true
		}
		return nil, false

	} else {
		return nil, false
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

	token, err := jwt.ParseWithClaims(parts[1], &userClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return false
	}

	_ = token
	if claims, ok := token.Claims.(*userClaims); ok && token.Valid {

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
