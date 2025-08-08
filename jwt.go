package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles JWT token generation and parsing using a secret key.
type jwtService struct {
	// Secret is the key used to sign and verify JWT tokens.
	secret string
	exp    time.Time
}

func NewJWTService(secret string, exp time.Time) *jwtService {
	return &jwtService{
		secret: secret,
		exp:    exp,
	}
}

// Generate creates a signed JWT token containing the provided data as claims.
// The token expires in 30 minutes. Returns the signed token string or an error.
func (j *jwtService) Generate(data any) (string, error) {
	claims := jwt.MapClaims{
		"data": data,
		"exp":  j.exp.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.secret))
}

// Parse validates and decodes a JWT token string, returning the embedded data
// if the token is valid and not expired. Returns an error if the token is invalid
// or cannot be parsed.
func (j *jwtService) Parse(tokenStr string) (any, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return []byte(j.secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: parsing token: %w", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		data, ok := claims["data"]
		if !ok {
			return nil, ErrInvalidToken
		}
		return data, nil
	}
	return nil, ErrInvalidToken
}
