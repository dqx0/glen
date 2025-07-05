package models

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	StatusActive   = "active"
	StatusInactive = "inactive"
)

var (
	ErrInvalidUsername = errors.New("invalid username")
	ErrInvalidEmail    = errors.New("invalid email")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUsernameTooLong = errors.New("username too long")
	
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

type User struct {
	ID             string    `json:"id" db:"id"`
	Username       string    `json:"username" db:"username"`
	Email          string    `json:"email" db:"email"`
	PasswordHash   string    `json:"-" db:"password_hash"`
	EmailVerified  bool      `json:"email_verified" db:"email_verified"`
	Status         string    `json:"status" db:"status"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
	OrganizationID *string   `json:"organization_id" db:"organization_id"`
	ParentUserID   *string   `json:"parent_user_id" db:"parent_user_id"`
}

func NewUser(username, email, password string) (*User, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	
	if email != "" {
		if err := validateEmail(email); err != nil {
			return nil, err
		}
	}
	
	user := &User{
		ID:            uuid.New().String(),
		Username:      username,
		Email:         email,
		EmailVerified: false,
		Status:        StatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	if password != "" {
		if err := user.setPassword(password); err != nil {
			return nil, err
		}
	}
	
	return user, nil
}

func (u *User) ValidatePassword(password string) bool {
	if u.PasswordHash == "" || password == "" {
		return false
	}
	
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

func (u *User) UpdatePassword(password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	
	if err := u.setPassword(password); err != nil {
		return err
	}
	
	u.UpdatedAt = time.Now()
	return nil
}

func (u *User) SetEmailVerified(verified bool) {
	u.EmailVerified = verified
	u.UpdatedAt = time.Now()
}

func (u *User) IsActive() bool {
	return u.Status == StatusActive
}

func (u *User) setPassword(password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	
	u.PasswordHash = string(hashedPassword)
	return nil
}

func validateUsername(username string) error {
	if username == "" {
		return ErrInvalidUsername
	}
	
	if len(username) > 50 {
		return ErrUsernameTooLong
	}
	
	// ユーザー名に使用できる文字の制限
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return ErrInvalidUsername
	}
	
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return nil // 空の場合は OK
	}
	
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	
	return nil
}

func validatePassword(password string) error {
	if password == "" {
		return ErrInvalidPassword
	}
	
	if len(password) < 8 {
		return ErrInvalidPassword
	}
	
	return nil
}