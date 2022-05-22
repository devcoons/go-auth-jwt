package auth_jwt

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gin-gonic/gin"
)

type jwtClaims struct {
	Data interface{} `json:"data"`
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

func (x *AuthJWT) GenerateJWT(data interface{}) string {
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

func (x *AuthJWT) IsAuthorized(r *http.Request) (interface{}, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return nil, false
	}

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(parts[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return nil, false
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
				return nil, false
			}
			return claims.Data, true
		}
		return nil, false
	} else {
		return nil, false
	}
}

func (x *AuthJWT) IsAuthorizedToken(stoken string) (interface{}, bool) {

	var mySigningKey = []byte(x.SecretKey)

	token, err := jwt.ParseWithClaims(stoken, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})

	if err != nil {
		return nil, false
	}

	_ = token
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {

		if x.invalidatedTokens == nil {
			x.invalidatedTokens = make(map[string]time.Time)
		}

		_, ok := x.invalidatedTokens[stoken]

		for key, val := range x.invalidatedTokens {
			if time.Now().After(val) {
				delete(x.invalidatedTokens, key)
			}
		}

		if !ok {
			tm := time.Unix(claims.ExpiresAt, 0)
			if time.Now().UTC().After(tm) {
				return nil, false
			}
			return claims.Data, true
		}
		return nil, false
	} else {
		return nil, false
	}
}
func (x *AuthJWT) IsAuthorizedWithKey(r *http.Request, key string) (interface{}, bool) {

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, false
	}

	parts := strings.SplitN(authorization, " ", 2)
	if parts[0] != "Bearer" {
		return nil, false
	}

	var mySigningKey = []byte(key)
	token, err := jwt.ParseWithClaims(parts[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("could not open")
		}
		return mySigningKey, nil
	})
	if err != nil {
		return nil, false
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
				return nil, false
			}
			return claims.Data, true
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

func (x *AuthJWT) InvalidateToken(utoken string) bool {
	for key, val := range x.invalidatedTokens {
		if time.Now().After(val) {
			delete(x.invalidatedTokens, key)
		}
	}

	var mySigningKey = []byte(x.SecretKey)
	token, err := jwt.ParseWithClaims(utoken, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
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
		_, ok := x.invalidatedTokens[utoken]
		if ok {
			return false
		}
		x.invalidatedTokens[utoken] = time.Unix(claims.ExpiresAt, 0)
	}
	return true
}
