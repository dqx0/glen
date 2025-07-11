package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
	"github.com/dqx0/glen/user-service/internal/webauthn/repository"
)

// simpleWebAuthnService is a simplified implementation focusing on core functionality
type simpleWebAuthnService struct {
	credRepo         repository.WebAuthnRepository
	sessionStore     repository.SessionStore
	challengeManager ChallengeManager
	config           *WebAuthnConfig
}

// NewSimpleWebAuthnService creates a simplified WebAuthn service for testing
func NewSimpleWebAuthnService(
	credRepo repository.WebAuthnRepository,
	sessionStore repository.SessionStore,
	config *WebAuthnConfig,
) (WebAuthnService, error) {
	if config == nil {
		return nil, ErrInvalidConfig("WebAuthn configuration is required")
	}
	
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	if credRepo == nil {
		return nil, ErrInvalidConfig("Credential repository is required")
	}
	
	if sessionStore == nil {
		return nil, ErrInvalidConfig("Session store is required")
	}

	challengeManager := NewChallengeManager(sessionStore, config)

	return &simpleWebAuthnService{
		credRepo:         credRepo,
		sessionStore:     sessionStore,
		challengeManager: challengeManager,
		config:           config,
	}, nil
}

// GetUserCredentials retrieves all credentials for a user
func (s *simpleWebAuthnService) GetUserCredentials(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	if userID == "" {
		return nil, ErrInvalidRequest("User ID is required")
	}

	credentials, err := s.credRepo.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credentials", "", err)
	}

	return credentials, nil
}

// UpdateCredential updates an existing credential
func (s *simpleWebAuthnService) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	if credential == nil {
		return ErrInvalidRequest("Credential is required")
	}

	if err := credential.Validate(); err != nil {
		return ErrInvalidCredentialData(err.Error())
	}

	if err := s.credRepo.UpdateCredential(ctx, credential); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to update credential", "", err)
	}

	return nil
}

// DeleteCredential deletes a credential for a user
func (s *simpleWebAuthnService) DeleteCredential(ctx context.Context, userID string, credentialID []byte) error {
	if userID == "" {
		return ErrInvalidRequest("User ID is required")
	}
	
	if len(credentialID) == 0 {
		return ErrInvalidRequest("Credential ID is required")
	}

	// Verify credential belongs to user
	credential, err := s.credRepo.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credential", "", err)
	}

	if credential.UserID != userID {
		return NewServiceError(ErrServiceAuthorization, "Credential does not belong to user", "")
	}

	if err := s.credRepo.DeleteCredential(ctx, credentialID); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to delete credential", "", err)
	}

	return nil
}

// GetCredentialStatistics returns statistics about stored credentials
func (s *simpleWebAuthnService) GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error) {
	repoStats, err := s.credRepo.GetCredentialStatistics(ctx)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credential statistics", "", err)
	}

	// Convert repository stats to service stats
	stats := &CredentialStatistics{
		TotalCredentials:         repoStats.TotalCredentials,
		ActiveCredentials:        repoStats.TotalCredentials, // Assume all are active for now
		CredentialsByTransport:   repoStats.CredentialsByTransport,
		CredentialsByAttestation: repoStats.CredentialsByAttestation,
		AvgCredentialsPerUser:    repoStats.AvgCredentialsPerUser,
		CreatedInLast24Hours:     repoStats.CreatedInLast24Hours,
		CreatedInLastWeek:        repoStats.CreatedInLastWeek,
		CreatedInLastMonth:       repoStats.CreatedInLastMonth,
		UsageStatistics:          &CredentialUsageStatistics{
			TotalAuthentications:     0,
			AuthenticationsLast24h:   0,
			AuthenticationsLastWeek:  0,
			AuthenticationsLastMonth: 0,
			MostActiveCredentials:    []CredentialActivity{},
			LeastActiveCredentials:   []CredentialActivity{},
		},
	}

	return stats, nil
}

// CleanupExpiredData removes expired sessions and old credentials
func (s *simpleWebAuthnService) CleanupExpiredData(ctx context.Context) error {
	// Cleanup expired sessions
	if err := s.challengeManager.CleanupExpiredSessions(ctx); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to cleanup expired sessions", "", err)
	}

	// Cleanup old credentials if configured
	if s.config.CredentialTimeout > 0 {
		retentionPeriod := 365 * 24 * time.Hour // 1 year default
		if err := s.credRepo.CleanupExpiredCredentials(ctx, retentionPeriod); err != nil {
			return NewServiceErrorWithCause(ErrServiceDependency, "Failed to cleanup expired credentials", "", err)
		}
	}

	return nil
}

// ValidateCredentialUsage validates credential usage patterns for security
func (s *simpleWebAuthnService) ValidateCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error {
	if !s.config.SignCountValidation {
		return nil
	}

	// Get current credential
	credential, err := s.credRepo.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credential for validation", "", err)
	}

	// Check for sign count regression (possible cloning)
	if signCount <= credential.SignCount && credential.SignCount > 0 {
		if s.config.CloneDetection {
			// Mark credential as potentially cloned
			credential.CloneWarning = true
			if err := s.credRepo.UpdateCredential(ctx, credential); err != nil {
				// Log warning but don't fail
			}
			
			return NewServiceError(ErrServiceAuthentication, "Potential credential cloning detected", 
				fmt.Sprintf("Sign count regression: current=%d, received=%d", credential.SignCount, signCount))
		}
	}

	return nil
}

// Simplified implementations for WebAuthn ceremony methods
// These would typically integrate with go-webauthn library

func (s *simpleWebAuthnService) BeginRegistration(ctx context.Context, req *RegistrationStartRequest) (*RegistrationStartResponse, error) {
	// Simplified implementation
	if req == nil || req.UserID == "" || req.Username == "" {
		return nil, ErrInvalidRequest("Invalid registration request")
	}

	// Check credential limit
	credCount, err := s.credRepo.GetCredentialCount(ctx, req.UserID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to check credential count", "", err)
	}
	
	if credCount >= s.config.MaxCredentialsPerUser {
		return nil, ErrCredentialLimit(req.UserID, s.config.MaxCredentialsPerUser)
	}

	// Generate challenge
	challenge, err := s.challengeManager.GenerateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	// Create session
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(s.config.ChallengeExpiry)
	
	session := &models.SessionData{
		ID:               sessionID,
		UserID:           req.UserID,
		Challenge:        challenge,
		ExpiresAt:        expiresAt,
		CreatedAt:        time.Now(),
		UserVerification: models.UserVerificationPreferred,
	}

	if err := s.challengeManager.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Return simplified creation options
	creationOptions := &models.PublicKeyCredentialCreationOptions{
		Challenge: challenge,
		RP: &models.RelyingPartyEntity{
			ID:   s.config.RPID,
			Name: s.config.RPName,
		},
		User: &models.UserEntity{
			ID:          []byte(req.UserID),
			Name:        req.Username,
			DisplayName: req.DisplayName,
		},
		PubKeyCredParams: models.DefaultCredentialParameters(),
	}

	return &RegistrationStartResponse{
		SessionID:       sessionID,
		CreationOptions: creationOptions,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *simpleWebAuthnService) FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (*RegistrationResult, error) {
	// Simplified implementation
	if req == nil || req.SessionID == "" {
		return &RegistrationResult{Success: false, Error: ErrInvalidRequest("Invalid registration finish request")}, nil
	}

	// Get session
	session, err := s.challengeManager.GetSession(ctx, req.SessionID)
	if err != nil {
		return &RegistrationResult{Success: false, Error: ErrSessionNotFound(req.SessionID)}, nil
	}

	if session.IsExpired() {
		s.challengeManager.InvalidateSession(ctx, req.SessionID)
		return &RegistrationResult{Success: false, Error: ErrSessionExpired(req.SessionID)}, nil
	}

	// In a real implementation, this would verify the attestation response
	// For simplicity, we'll create a credential directly
	credential := &models.WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          session.UserID,
		CredentialID:    []byte(uuid.New().String()), // Would come from attestation response
		PublicKey:       []byte("mock-public-key"),   // Would come from attestation response
		AttestationType: "none",
		Transport: []models.AuthenticatorTransport{
			models.TransportUSB,
		},
		Flags: models.AuthenticatorFlags{
			UserPresent: true,
		},
		SignCount: 0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.credRepo.CreateCredential(ctx, credential); err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to store credential", "", err),
		}, nil
	}

	s.challengeManager.InvalidateSession(ctx, req.SessionID)

	return &RegistrationResult{
		Success:      true,
		CredentialID: string(credential.CredentialID),
		Credential:   credential,
	}, nil
}

func (s *simpleWebAuthnService) BeginAuthentication(ctx context.Context, req *AuthenticationStartRequest) (*AuthenticationStartResponse, error) {
	// Simplified implementation
	if req == nil {
		return nil, ErrInvalidRequest("Invalid authentication request")
	}

	userID := req.UserID
	if userID == "" && req.UserIdentifier != "" {
		userID = req.UserIdentifier
	}

	if userID == "" {
		return nil, ErrInvalidRequest("Either user_id or user_identifier must be provided")
	}

	// Get user credentials
	credentials, err := s.credRepo.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get user credentials", "", err)
	}

	if len(credentials) == 0 {
		return nil, ErrCredentialNotFound("No credentials found for user")
	}

	// Generate challenge
	challenge, err := s.challengeManager.GenerateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	// Create session
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(s.config.ChallengeExpiry)
	
	allowedCredentialIDs := make([][]byte, len(credentials))
	for i, cred := range credentials {
		allowedCredentialIDs[i] = cred.CredentialID
	}
	
	session := &models.SessionData{
		ID:                   sessionID,
		UserID:               userID,
		Challenge:            challenge,
		AllowedCredentialIDs: allowedCredentialIDs,
		ExpiresAt:            expiresAt,
		CreatedAt:            time.Now(),
		UserVerification:     models.UserVerificationPreferred,
	}

	if err := s.challengeManager.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Return simplified request options
	allowCredentials := make([]models.CredentialDescriptor, len(credentials))
	for i, cred := range credentials {
		allowCredentials[i] = models.CredentialDescriptor{
			Type:       "public-key",
			ID:         cred.CredentialID,
			Transports: cred.Transport,
		}
	}

	requestOptions := &models.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RPID:             s.config.RPID,
		AllowCredentials: allowCredentials,
		UserVerification: models.UserVerificationPreferred,
	}

	return &AuthenticationStartResponse{
		SessionID:      sessionID,
		RequestOptions: requestOptions,
		ExpiresAt:      expiresAt,
	}, nil
}

func (s *simpleWebAuthnService) FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (*AuthenticationResult, error) {
	// Simplified implementation
	if req == nil || req.SessionID == "" {
		return &AuthenticationResult{Success: false, Error: ErrInvalidRequest("Invalid authentication finish request")}, nil
	}

	// Get session
	session, err := s.challengeManager.GetSession(ctx, req.SessionID)
	if err != nil {
		return &AuthenticationResult{Success: false, Error: ErrSessionNotFound(req.SessionID)}, nil
	}

	if session.IsExpired() {
		s.challengeManager.InvalidateSession(ctx, req.SessionID)
		return &AuthenticationResult{Success: false, Error: ErrSessionExpired(req.SessionID)}, nil
	}

	// In a real implementation, this would verify the assertion response
	// For simplicity, we'll simulate a successful authentication
	
	s.challengeManager.InvalidateSession(ctx, req.SessionID)

	return &AuthenticationResult{
		Success:            true,
		UserID:             session.UserID,
		CredentialID:       "mock-credential-id",
		SignCount:          1,
		AuthenticationTime: time.Now(),
	}, nil
}