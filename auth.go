// Package auth provides authentication and user management services,
// including user creation, login, password reset, and email verification.
// It supports JWT-based token handling, rate limiting, and integration
// with external token delivery mechanisms.
package auth

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/time/rate"
)

var (
	// ErrTooManyRequests is returned when the rate limiter blocks a request.
	ErrTooManyRequests = errors.New("too many requests")
	// ErrInvalidToken is returned when a provided token is invalid or cannot be parsed.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidCredentials is returned when login credentials are incorrect.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotFound is returned when a user cannot be found in the store.
	ErrUserNotFound = errors.New("user not found")
)

// tokenSender defines the interface for sending authentication tokens
// to users via email or other delivery mechanisms.
type tokenSender interface {
	SendPasswordResetEmail(email, token string) error
	SendVerificationEmail(email, token string) error
}

// emailToken represents the payload for email-based token operations.
type emailToken struct {
	Email string `json:"email"`
}

// NewAuthService creates a new instance of authService with the provided
// user store, JWT service, token sender, and optional rate limiter.
func NewAuthService(store UserStore, jwt *jwtService, sender tokenSender, limiter *rate.Limiter) *authService {
	return &authService{
		store:   store,
		jwt:     jwt,
		sender:  sender,
		limiter: limiter,
	}
}

// authService implements authentication and user management operations.
// It uses a user store for persistence, JWT for token handling, a token
// sender for email delivery, and an optional rate limiter for request control.
type authService struct {
	store  UserStore
	jwt    *jwtService
	sender tokenSender

	// Rate limiter for controlling requests per endpoint.
	// You can adjust the rate and burst as needed.
	limiter *rate.Limiter
}

// CreateUser creates a new user with the specified name and password,
// using the provided token for email verification. Returns an error if
// rate limited, token is invalid, or user creation fails.
func (a *authService) CreateUser(name, password, token string) error {
	if a.limiter != nil && !a.limiter.Allow() {
		return ErrTooManyRequests
	}

	res, err := a.jwt.Parse(token)
	if err != nil {
		return fmt.Errorf("%w: parsing token: %w", ErrInvalidToken, err)
	}

	data, ok := res.(emailToken)
	if !ok {
		return ErrInvalidToken
	}

	hashed, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	user := User{
		Email:     data.Email,
		Name:      name,
		Password:  hashed,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return a.store.CreateUser(user)
}

// Login authenticates a user by email and password. Returns a JWT token
// if successful, or an error if rate limited, user not found, or credentials are invalid.
func (a *authService) Login(email, password string) (string, error) {
	if a.limiter != nil && !a.limiter.Allow() {
		return "", ErrTooManyRequests
	}

	user, err := a.store.GetUserByEmail(email)
	if err != nil {
		return "", fmt.Errorf("getting user by email: %w", err)
	}

	if !CheckPasswordHash(user.Password, password) {
		return "", ErrInvalidCredentials
	}
	return a.jwt.Generate(user)
}

// ForgotPassword initiates a password reset for the specified email.
// Generates a reset token and sends it via the token sender. Returns an error
// if rate limited, user not found, or token delivery fails.
func (a *authService) ForgotPassword(email string) error {
	if a.limiter != nil && !a.limiter.Allow() {
		return ErrTooManyRequests
	}

	user, err := a.store.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("getting user by email: %w", err)
	}
	token, err := a.jwt.Generate(emailToken{Email: user.Email})
	if err != nil {
		return fmt.Errorf("generating jwt: %w", err)
	}

	if err := a.sender.SendPasswordResetEmail(email, token); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}
	// Normally you'd email this token. Here we return it.
	return nil
}

// VerifyEmail sends a verification token to the specified email address.
// Returns an error if rate limited or token delivery fails.
func (a *authService) VerifyEmail(email string) error {
	if a.limiter != nil && !a.limiter.Allow() {
		return ErrTooManyRequests
	}
	// Sign the email using JWT
	data := emailToken{
		Email: email,
	}

	token, err := a.jwt.Generate(data)
	if err != nil {
		return fmt.Errorf("generating jwt: %w", err)
	}

	if err := a.sender.SendVerificationEmail(email, token); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}

// ResetPassword resets the user's password using the provided token and new password.
// Returns an error if rate limited, token is invalid, user not found, or update fails.
func (a *authService) ResetPassword(token, newPassword string) error {
	if a.limiter != nil && !a.limiter.Allow() {
		return ErrTooManyRequests
	}

	res, err := a.jwt.Parse(token)
	if err != nil {
		return fmt.Errorf("%w: parsing token: %w", ErrInvalidToken, err)
	}

	data, ok := res.(emailToken)
	if !ok {
		return ErrInvalidToken
	}

	user, err := a.store.GetUserByEmail(data.Email)
	if err != nil {
		return fmt.Errorf("getting user by email: %w", err)
	}

	hashed, _ := HashPassword(newPassword)
	user.Password = hashed
	user.UpdatedAt = time.Now()

	if err := a.store.UpdateUser(user); err != nil {
		return err
	}

	return nil
}
