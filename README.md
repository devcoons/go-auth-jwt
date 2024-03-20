# go-auth-jwt

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/devcoons/go-auth-jwt?style=for-the-badge)
![GitHub License](https://img.shields.io/github/license/devcoons/go-auth-jwt?style=for-the-badge)

The `go-auth-jwt` package offers a streamlined approach for implementing JSON Web Tokens (JWT) authentication within Go applications. It's specifically tailored for use with the Gin web framework, simplifying the process of generating, validating, and invalidating JWTs.

## Features

- Easy generation of JWT tokens with custom payload.
- Middleware integration for Gin for easy setup.
- Support for token validation within HTTP requests.
- Methods for invalidating tokens to handle logout scenarios.
- Customizable token duration and secret key.

## Structs

### AuthJWT

- `SecretKey`: The secret key used for signing tokens.
- `TokenDuration`: The duration for which the token remains valid.
- `invalidatedTokens`: A map to track invalidated tokens.
- `AuthType`: The authorization type, typically "Bearer".

## Functions

`ApiMiddleware(name string, j *AuthJWT) gin.HandlerFunc`

Middleware function that attaches an `AuthJWT` instance to the Gin context.

`GenerateJWT(data interface{}) string`

Creates a JWT token with the given payload. Returns the token or an empty string on failure.

`IsAuthorized(r *http.Request) (interface{}, bool)`

Validates the JWT token in the request's Authorization header, returning the payload and a boolean indicating if the token is valid.

`IsAuthorizedToken(stoken string) (interface{}, bool)`

Validates a given JWT token string, returning the payload and a validity boolean.

`IsAuthorizedWithKey(r *http.Request, key string) (interface{}, bool)`

Validates the request's token with a specified key, useful for multi-key setups.

`InvalidateJWT(r *http.Request) bool`

Invalidates the token found in the request's Authorization header.

`InvalidateToken(utoken string) bool`

Invalidates a specified token string.

## Installation

To use `go-auth-jwt` in your project, run:

```
go get github.com/devcoons/go-auth-jwt
```

## Getting Started

Import `go-auth-jwt` and other necessary packages:

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/devcoons/go-auth-jwt"
    "net/http"
    "time"
)
```
Initialize AuthJWT with your configuration:

```go
auth := auth_jwt.AuthJWT{
    SecretKey:     "yourSecretKeyHere",
    TokenDuration: 24 * time.Hour,
    AuthType:      "Bearer",
}
```

Integrate with Gin by adding the middleware:

```go
router.Use(auth_jwt.ApiMiddleware("jwt", &auth))

```

## Examples

### Generating a Token

```go
token := auth.GenerateJWT(map[string]interface{}{"user": "exampleUser"})

```

### Validating a Request

```go
router.GET("/protected", func(c *gin.Context) {
    _, authorized := auth.IsAuthorized(c.Request)
    if !authorized {
        c.AbortWithStatus(http.StatusUnauthorized)
        return
    }
    // Your handler logic here
})

```

### Invalidating a Token
```go
router.POST("/logout", func(c *gin.Context) {
    if auth.InvalidateJWT(c.Request) {
        c.Status(http.StatusOK)
    } else {
        c.Status(http.StatusInternalServerError)
    }
})

```