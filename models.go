package auth

import "time"

// User represents an application user with identifying and authentication information.
// Password is stored as a bcrypt hash. Timestamps track creation and last update.
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	Password  string    `json:"-"` // Hashed
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// UserStore defines the interface for user persistence and retrieval operations.
// It supports user creation, lookup by email or ID, updates, and password reset token management.
type UserStore interface {
	CreateUser(user User) error
	GetUserByEmail(email string) (User, error)
	GetUserByID(id string) (User, error)
	UpdateUser(user User) error
	SaveResetToken(token string, userID string, expiresIn time.Duration) error
	GetUserIDByResetToken(token string) (string, error)
	DeleteResetToken(token string) error
}
