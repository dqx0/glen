package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// redisSessionStore implements SessionStore for Redis
type redisSessionStore struct {
	client  *redis.Client
	config  *RepositoryConfig
	timeout time.Duration
	keyPrefix string
}

// NewRedisSessionStore creates a new Redis session store
func NewRedisSessionStore(client *redis.Client, config *RepositoryConfig) SessionStore {
	if config == nil {
		config = &RepositoryConfig{
			QueryTimeout: 30 * time.Second,
			SessionCleanupInterval: 1 * time.Hour,
			MaxSessionsPerUser: 5,
		}
	}
	
	return &redisSessionStore{
		client:    client,
		config:    config,
		timeout:   config.QueryTimeout,
		keyPrefix: "webauthn:session:",
	}
}

// StoreSession stores a WebAuthn session in Redis
func (s *redisSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Validate session before storage
	if err := session.Validate(); err != nil {
		return NewRepositoryError(ErrRepositoryConstraint, "Invalid session data", err)
	}

	key := s.keyPrefix + session.ID

	// Check if session already exists
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to check session existence", err)
	}

	if exists > 0 {
		return NewRepositoryError(ErrRepositoryConflict, "Session ID already exists", nil)
	}

	// Serialize session data
	sessionData, err := json.Marshal(session)
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to serialize session", err)
	}

	// Calculate TTL based on session expiry
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return NewRepositoryError(ErrRepositoryConstraint, "Session already expired", nil)
	}

	// Store session with TTL
	err = s.client.SetEX(ctx, key, sessionData, ttl).Err()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to store session", err)
	}

	// Manage session count per user
	if err := s.enforceSessionLimit(ctx, session.UserID); err != nil {
		// Log warning but don't fail the session storage
		// In a production system, you might want to log this properly
		_ = err
	}

	return nil
}

// GetSession retrieves a session from Redis
func (s *redisSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := s.keyPrefix + sessionID

	// Get session data
	sessionData, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NewRepositoryError(ErrRepositoryNotFound, "Session not found", err)
		}
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get session", err)
	}

	// Deserialize session data
	var session models.SessionData
	err = json.Unmarshal([]byte(sessionData), &session)
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to deserialize session", err)
	}

	// Check if session has expired (double-check)
	if session.IsExpired() {
		// Remove expired session
		_ = s.client.Del(ctx, key)
		return nil, NewRepositoryError(ErrRepositoryNotFound, "Session expired", nil)
	}

	return &session, nil
}

// DeleteSession removes a session from Redis
func (s *redisSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := s.keyPrefix + sessionID

	result, err := s.client.Del(ctx, key).Result()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to delete session", err)
	}

	if result == 0 {
		return NewRepositoryError(ErrRepositoryNotFound, "Session not found", nil)
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions from Redis
func (s *redisSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Redis automatically handles TTL expiration, but we can also manually scan
	// for any sessions that might have slipped through or have custom cleanup logic

	pattern := s.keyPrefix + "*"
	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()

	var expiredKeys []string
	for iter.Next(ctx) {
		key := iter.Val()
		
		// Get session to check if expired
		sessionData, err := s.client.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				continue // Already deleted
			}
			// Log error but continue
			continue
		}

		var session models.SessionData
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			// Invalid session data, mark for deletion
			expiredKeys = append(expiredKeys, key)
			continue
		}

		if session.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	if err := iter.Err(); err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to scan sessions", err)
	}

	// Delete expired sessions
	if len(expiredKeys) > 0 {
		_, err := s.client.Del(ctx, expiredKeys...).Result()
		if err != nil {
			return NewRepositoryError(ErrRepositoryInternal, "Failed to delete expired sessions", err)
		}
	}

	return nil
}

// GetActiveSessionCount returns the number of active sessions
func (s *redisSessionStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	pattern := s.keyPrefix + "*"
	
	// Use SCAN to count keys
	var count int
	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		count++
	}

	if err := iter.Err(); err != nil {
		return 0, NewRepositoryError(ErrRepositoryInternal, "Failed to count sessions", err)
	}

	return count, nil
}

// GetSessionsByUserID returns all sessions for a specific user
func (s *redisSessionStore) GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := validateUUID(userID); err != nil {
		return nil, NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", err)
	}

	pattern := s.keyPrefix + "*"
	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()

	var sessions []*models.SessionData
	for iter.Next(ctx) {
		key := iter.Val()
		
		sessionData, err := s.client.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			continue // Skip this session
		}

		var session models.SessionData
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			continue // Skip invalid session
		}

		if session.UserID == userID && !session.IsExpired() {
			sessions = append(sessions, &session)
		}
	}

	if err := iter.Err(); err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan user sessions", err)
	}

	return sessions, nil
}

// ValidateSessionExists checks if a session exists for a specific user
func (s *redisSessionStore) ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		if IsRepositoryError(err) && GetRepositoryError(err).Type == ErrRepositoryNotFound {
			return false, nil
		}
		return false, err
	}

	return session.UserID == userID, nil
}

// ExtendSessionExpiry extends the expiry time of a session
func (s *redisSessionStore) ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := s.keyPrefix + sessionID

	// Get current session
	session, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Update expiry time
	session.ExpiresAt = newExpiry

	// Re-store with new TTL
	sessionData, err := json.Marshal(session)
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to serialize session", err)
	}

	ttl := time.Until(newExpiry)
	if ttl <= 0 {
		return NewRepositoryError(ErrRepositoryConstraint, "New expiry time is in the past", nil)
	}

	err = s.client.SetEX(ctx, key, sessionData, ttl).Err()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to extend session expiry", err)
	}

	return nil
}

// enforceSessionLimit ensures a user doesn't exceed the maximum session count
func (s *redisSessionStore) enforceSessionLimit(ctx context.Context, userID string) error {
	sessions, err := s.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if len(sessions) <= s.config.MaxSessionsPerUser {
		return nil
	}

	// Remove oldest sessions
	excessSessions := len(sessions) - s.config.MaxSessionsPerUser

	// Sort sessions by creation time (oldest first)
	for i := 0; i < len(sessions)-1; i++ {
		for j := i + 1; j < len(sessions); j++ {
			if sessions[i].CreatedAt.After(sessions[j].CreatedAt) {
				sessions[i], sessions[j] = sessions[j], sessions[i]
			}
		}
	}

	// Delete excess sessions
	for i := 0; i < excessSessions; i++ {
		if err := s.DeleteSession(ctx, sessions[i].ID); err != nil {
			// Log warning but continue
			continue
		}
	}

	return nil
}

// Additional utility methods for Redis session store

// SetSessionCleanupInterval configures automatic cleanup
func (s *redisSessionStore) SetSessionCleanupInterval(interval time.Duration) {
	s.config.SessionCleanupInterval = interval
}

// GetKeyPrefix returns the Redis key prefix used for sessions
func (s *redisSessionStore) GetKeyPrefix() string {
	return s.keyPrefix
}

// FlushAllSessions removes all WebAuthn sessions (use with caution)
func (s *redisSessionStore) FlushAllSessions(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	pattern := s.keyPrefix + "*"
	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()

	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to scan sessions for flush", err)
	}

	if len(keys) > 0 {
		_, err := s.client.Del(ctx, keys...).Result()
		if err != nil {
			return NewRepositoryError(ErrRepositoryInternal, "Failed to flush sessions", err)
		}
	}

	return nil
}

// GetSessionTTL returns the remaining TTL for a session
func (s *redisSessionStore) GetSessionTTL(ctx context.Context, sessionID string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := s.keyPrefix + sessionID

	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, NewRepositoryError(ErrRepositoryInternal, "Failed to get session TTL", err)
	}

	if ttl == -2 { // Key doesn't exist
		return 0, NewRepositoryError(ErrRepositoryNotFound, "Session not found", nil)
	}

	if ttl == -1 { // Key exists but has no TTL
		return 0, NewRepositoryError(ErrRepositoryInternal, "Session has no expiry", nil)
	}

	return ttl, nil
}

// WebAuthn-specific session storage methods for go-webauthn library integration

// StoreWebAuthnSession stores raw WebAuthn session data
func (s *redisSessionStore) StoreWebAuthnSession(ctx context.Context, sessionID string, sessionData []byte) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := "webauthn:raw:" + sessionID

	// Store with default 15 minute TTL
	ttl := 15 * time.Minute
	err := s.client.SetEX(ctx, key, sessionData, ttl).Err()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to store WebAuthn session", err)
	}

	return nil
}

// GetWebAuthnSession retrieves raw WebAuthn session data
func (s *redisSessionStore) GetWebAuthnSession(ctx context.Context, sessionID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := "webauthn:raw:" + sessionID

	sessionData, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NewRepositoryError(ErrRepositoryNotFound, "WebAuthn session not found", err)
		}
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get WebAuthn session", err)
	}

	return []byte(sessionData), nil
}

// DeleteWebAuthnSession removes raw WebAuthn session data
func (s *redisSessionStore) DeleteWebAuthnSession(ctx context.Context, sessionID string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	key := "webauthn:raw:" + sessionID

	result, err := s.client.Del(ctx, key).Result()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to delete WebAuthn session", err)
	}

	if result == 0 {
		return NewRepositoryError(ErrRepositoryNotFound, "WebAuthn session not found", nil)
	}

	return nil
}