package auth

import (
	"log/slog"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes the provided password using bcrypt and returns the hashed string.
// Returns an error if hashing fails.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a bcrypt hashed password with its possible plaintext equivalent.
// Returns true if the password matches the hash.
func CheckPasswordHash(hash, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		slog.Info("bcrypt.CompareHashAndPassword", "error", err)
		return false
	}
	return true
}
