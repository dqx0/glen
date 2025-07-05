package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredentialID = errors.New("invalid credential ID")
	ErrInvalidPublicKey    = errors.New("invalid public key")
	ErrInvalidUserID       = errors.New("invalid user ID")
)

type WebAuthnCredential struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	CredentialID string    `json:"credential_id" db:"credential_id"`
	PublicKey    []byte    `json:"public_key" db:"public_key"`
	Counter      int64     `json:"counter" db:"counter"`
	Name         string    `json:"name" db:"name"`
	Transport    string    `json:"transport" db:"transport"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at" db:"last_used_at"`
}

func NewWebAuthnCredential(userID, credentialID string, publicKey []byte, name, transport string) (*WebAuthnCredential, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	if credentialID == "" {
		return nil, ErrInvalidCredentialID
	}
	
	if len(publicKey) == 0 {
		return nil, ErrInvalidPublicKey
	}
	
	return &WebAuthnCredential{
		ID:           uuid.New().String(),
		UserID:       userID,
		CredentialID: credentialID,
		PublicKey:    publicKey,
		Counter:      0,
		Name:         name,
		Transport:    transport,
		CreatedAt:    time.Now(),
	}, nil
}

func (c *WebAuthnCredential) UpdateCounter(counter int64) {
	c.Counter = counter
	c.LastUsedAt = time.Now()
}

func (c *WebAuthnCredential) IsValid() bool {
	return c.UserID != "" && c.CredentialID != "" && len(c.PublicKey) > 0
}