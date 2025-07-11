package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/repository"
)

// challengeManager implements ChallengeManager
type challengeManager struct {
	sessionStore repository.SessionStore
	config       *WebAuthnConfig
}

// NewChallengeManager creates a new challenge manager
func NewChallengeManager(sessionStore repository.SessionStore, config *WebAuthnConfig) ChallengeManager {
	return &challengeManager{
		sessionStore: sessionStore,
		config:       config,
	}
}

// GenerateChallenge generates a cryptographically secure random challenge
func (cm *challengeManager) GenerateChallenge(ctx context.Context) ([]byte, error) {
	challenge := make([]byte, cm.config.ChallengeLength)
	
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceInternal, "Failed to generate challenge", "", err)
	}
	
	return challenge, nil
}

// ValidateChallenge validates a challenge against the stored session
func (cm *challengeManager) ValidateChallenge(ctx context.Context, sessionID string, challenge []byte) error {
	session, err := cm.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	
	// Compare challenges
	if !bytesEqual(session.Challenge, challenge) {
		return ErrChallengeValidation()
	}
	
	return nil
}

// CreateSession creates a new session in the store
func (cm *challengeManager) CreateSession(ctx context.Context, session *models.SessionData) error {
	if err := session.Validate(); err != nil {
		return ErrInvalidRequest("Invalid session data: " + err.Error())
	}
	
	if err := cm.sessionStore.StoreSession(ctx, session); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to store session", "", err)
	}
	
	return nil
}

// GetSession retrieves a session from the store
func (cm *challengeManager) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	session, err := cm.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		if repository.IsRepositoryError(err) {
			repoErr := repository.GetRepositoryError(err)
			if repoErr.Type == repository.ErrRepositoryNotFound {
				return nil, ErrSessionNotFound(sessionID)
			}
		}
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get session", "", err)
	}
	
	return session, nil
}

// InvalidateSession removes a session from the store
func (cm *challengeManager) InvalidateSession(ctx context.Context, sessionID string) error {
	if err := cm.sessionStore.DeleteSession(ctx, sessionID); err != nil {
		// Don't fail if session doesn't exist
		if repository.IsRepositoryError(err) {
			repoErr := repository.GetRepositoryError(err)
			if repoErr.Type == repository.ErrRepositoryNotFound {
				return nil
			}
		}
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to invalidate session", "", err)
	}
	
	return nil
}

// CleanupExpiredSessions removes expired sessions from the store
func (cm *challengeManager) CleanupExpiredSessions(ctx context.Context) error {
	if err := cm.sessionStore.CleanupExpiredSessions(ctx); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to cleanup expired sessions", "", err)
	}
	
	return nil
}

// Helper function to securely compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}

// Helper function to encode challenge for logging (without exposing the actual challenge)
func encodeChallengeForLogging(challenge []byte) string {
	if len(challenge) < 8 {
		return "***"
	}
	// Only show first and last few bytes for debugging
	return base64.URLEncoding.EncodeToString(challenge[:4]) + "..." + base64.URLEncoding.EncodeToString(challenge[len(challenge)-4:])
}