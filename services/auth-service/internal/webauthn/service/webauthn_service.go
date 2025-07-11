package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/dqx0/glen/auth-service/internal/webauthn/config"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/repository"
)

// webAuthnService implements WebAuthnService with full go-webauthn integration
type webAuthnService struct {
	webAuthn         *webauthn.WebAuthn
	credRepo         repository.WebAuthnRepository
	sessionStore     repository.SessionStore
	challengeManager ChallengeManager
	config           *config.WebAuthnConfig
	serviceConfig    *WebAuthnConfig
	userService      UserService // User service for user data retrieval
}

// NewWebAuthnService creates a new WebAuthn service with minimal dependencies for testing
func NewWebAuthnService(
	webAuthn *webauthn.WebAuthn,
	credRepo repository.WebAuthnRepository,
	sessionStore repository.SessionStore,
	challengeManager ChallengeManager,
	config *WebAuthnConfig,
) (WebAuthnService, error) {
	if config == nil {
		return nil, ErrInvalidConfig("WebAuthn configuration is required")
	}
	
	if webAuthn == nil {
		return nil, ErrInvalidConfig("WebAuthn instance is required")
	}
	
	if credRepo == nil {
		return nil, ErrInvalidConfig("Credential repository is required")
	}
	
	if sessionStore == nil {
		return nil, ErrInvalidConfig("Session store is required")
	}
	
	// Use provided challenge manager or create default
	if challengeManager == nil {
		challengeManager = NewChallengeManager(sessionStore, config)
	}
	
	return &webAuthnService{
		webAuthn:         webAuthn,
		credRepo:         credRepo,
		sessionStore:     sessionStore,
		challengeManager: challengeManager,
		serviceConfig:    config,
		userService:      CreateDefaultMockUsers(),
	}, nil
}

// NewWebAuthnService creates a new WebAuthn service with go-webauthn integration
func NewWebAuthnServiceFromConfig(
	credRepo repository.WebAuthnRepository,
	sessionStore repository.SessionStore,
	cfg *config.WebAuthnConfig,
) (WebAuthnService, error) {
	return NewWebAuthnServiceWithUserService(credRepo, sessionStore, cfg, CreateDefaultMockUsers())
}

// NewWebAuthnServiceWithUserService creates a new WebAuthn service with custom user service
func NewWebAuthnServiceWithUserService(
	credRepo repository.WebAuthnRepository,
	sessionStore repository.SessionStore,
	cfg *config.WebAuthnConfig,
	userService UserService,
) (WebAuthnService, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig("WebAuthn configuration is required")
	}
	
	if err := cfg.Validate(); err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceConfiguration, "Invalid WebAuthn configuration", "", err)
	}
	
	if credRepo == nil {
		return nil, ErrInvalidConfig("Credential repository is required")
	}
	
	if sessionStore == nil {
		return nil, ErrInvalidConfig("Session store is required")
	}

	// Convert config to go-webauthn format
	webAuthnConfig := cfg.ToWebAuthnConfig()
	
	// Initialize WebAuthn library
	webAuthn, err := webauthn.New(webAuthnConfig)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceConfiguration, "Failed to initialize WebAuthn", "", err)
	}

	// Create service config with defaults
	serviceConfig := &WebAuthnConfig{
		RPID:                      cfg.RPID,
		RPName:                    cfg.RPDisplayName,
		RPIcon:                    cfg.RPIcon,
		ChallengeLength:           32,
		ChallengeExpiry:           5 * time.Minute,
		SessionTimeout:            15 * time.Minute,
		MaxSessions:               5,
		RequireUserVerification:   false,
		AllowedOrigins:           cfg.RPOrigins,
		CredentialTimeout:        60 * time.Second,
		MaxCredentialsPerUser:    10,
		RequireResidentKey:       false,
		UserVerification:         "preferred",
		AttestationPreference:    "none",
		SignCountValidation:      true,
		CloneDetection:          true,
	}

	if err := serviceConfig.Validate(); err != nil {
		return nil, err
	}

	challengeManager := NewChallengeManager(sessionStore, serviceConfig)

	return &webAuthnService{
		webAuthn:         webAuthn,
		credRepo:         credRepo,
		sessionStore:     sessionStore,
		challengeManager: challengeManager,
		config:           cfg,
		serviceConfig:    serviceConfig,
		userService:      userService,
	}, nil
}

// userAdapter adapts database user to WebAuthn user interface
type userAdapter struct {
	userID      []byte
	username    string
	displayName string
	credentials []webauthn.Credential
}

func (u *userAdapter) WebAuthnID() []byte {
	return u.userID
}

func (u *userAdapter) WebAuthnName() string {
	return u.username
}

func (u *userAdapter) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *userAdapter) WebAuthnIcon() string {
	return ""
}

func (u *userAdapter) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// credentialAdapter converts models.WebAuthnCredential to webauthn.Credential
func (s *webAuthnService) convertToWebAuthnCredential(cred *models.WebAuthnCredential) webauthn.Credential {
	return webauthn.Credential{
		ID:        cred.CredentialID,
		PublicKey: cred.PublicKey,
		AttestationType: cred.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte{}, // Would need to be extracted from attestation
			SignCount: cred.SignCount,
			CloneWarning: cred.CloneWarning,
		},
	}
}

// convertFromWebAuthnCredential converts webauthn.Credential to models.WebAuthnCredential
func (s *webAuthnService) convertFromWebAuthnCredential(userID string, cred *webauthn.Credential) *models.WebAuthnCredential {
	now := time.Now()
	
	return &models.WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          userID,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       []models.AuthenticatorTransport{models.TransportInternal}, // Default, should be set from client
		Flags: models.AuthenticatorFlags{
			UserPresent:    true, // Would be extracted from authenticator data
			UserVerified:   false,
			BackupEligible: false,
			BackupState:    false,
		},
		SignCount:    cred.Authenticator.SignCount,
		CloneWarning: cred.Authenticator.CloneWarning,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// BeginRegistration starts the WebAuthn registration ceremony
func (s *webAuthnService) BeginRegistration(ctx context.Context, req *RegistrationStartRequest) (*RegistrationStartResponse, error) {
	if req == nil || req.UserID == "" || req.Username == "" {
		return nil, ErrInvalidRequest("Invalid registration request: user_id and username are required")
	}

	// Validate user ID format
	if _, err := uuid.Parse(req.UserID); err != nil {
		return nil, ErrInvalidRequest("Invalid user_id format: must be a valid UUID")
	}

	// Check credential limit
	credCount, err := s.credRepo.GetCredentialCount(ctx, req.UserID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to check credential count", "", err)
	}
	
	if credCount >= s.serviceConfig.MaxCredentialsPerUser {
		return nil, ErrCredentialLimit(req.UserID, s.serviceConfig.MaxCredentialsPerUser)
	}

	// Get existing credentials to exclude
	existingCreds, err := s.credRepo.GetCredentialsByUserID(ctx, req.UserID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get existing credentials", "", err)
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, len(existingCreds))
	for i, cred := range existingCreds {
		webauthnCreds[i] = s.convertToWebAuthnCredential(cred)
	}

	// Create user adapter
	user := &userAdapter{
		userID:      []byte(req.UserID),
		username:    req.Username,
		displayName: req.DisplayName,
		credentials: webauthnCreds,
	}
	
	if user.displayName == "" {
		user.displayName = req.Username
	}

	// Set registration options
	var registrationOptions []webauthn.RegistrationOption
	
	if req.Options != nil {
		if req.Options.ResidentKeyRequirement != "" {
			switch req.Options.ResidentKeyRequirement {
			case models.ResidentKeyRequired:
				registrationOptions = append(registrationOptions, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
			case models.ResidentKeyPreferred:
				registrationOptions = append(registrationOptions, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
			case models.ResidentKeyDiscouraged:
				registrationOptions = append(registrationOptions, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementDiscouraged))
			}
		}

		if req.Options.UserVerification != "" {
			switch req.Options.UserVerification {
			case models.UserVerificationRequired:
				registrationOptions = append(registrationOptions, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					UserVerification: protocol.VerificationRequired,
				}))
			case models.UserVerificationPreferred:
				registrationOptions = append(registrationOptions, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					UserVerification: protocol.VerificationPreferred,
				}))
			case models.UserVerificationDiscouraged:
				registrationOptions = append(registrationOptions, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					UserVerification: protocol.VerificationDiscouraged,
				}))
			}
		}

		if req.Options.AttestationConveyancePreference != "" {
			switch req.Options.AttestationConveyancePreference {
			case models.AttestationConveyanceNone:
				registrationOptions = append(registrationOptions, webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
			case models.AttestationConveyanceIndirect:
				registrationOptions = append(registrationOptions, webauthn.WithConveyancePreference(protocol.PreferIndirectAttestation))
			case models.AttestationConveyanceDirect:
				registrationOptions = append(registrationOptions, webauthn.WithConveyancePreference(protocol.PreferDirectAttestation))
			}
		}

		if req.Options.AuthenticatorAttachment != "" {
			switch req.Options.AuthenticatorAttachment {
			case models.AuthenticatorAttachmentPlatform:
				registrationOptions = append(registrationOptions, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					AuthenticatorAttachment: protocol.Platform,
				}))
			case models.AuthenticatorAttachmentCrossPlatform:
				registrationOptions = append(registrationOptions, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					AuthenticatorAttachment: protocol.CrossPlatform,
				}))
			}
		}

		// Note: Timeout option may not be available in this version of go-webauthn
		// if req.Options.Timeout != nil && *req.Options.Timeout > 0 {
		//	timeoutDuration := time.Duration(*req.Options.Timeout) * time.Millisecond
		//	registrationOptions = append(registrationOptions, webauthn.WithCredentialTimeout(timeoutDuration))
		// }

		// Exclude existing credentials if requested
		if len(req.Options.ExcludeCredentials) > 0 {
			excludeList := make([]protocol.CredentialDescriptor, len(req.Options.ExcludeCredentials))
			for i, credID := range req.Options.ExcludeCredentials {
				excludeList[i] = protocol.CredentialDescriptor{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: credID,
				}
			}
			registrationOptions = append(registrationOptions, webauthn.WithExclusions(excludeList))
		}
	}

	// Begin registration with WebAuthn library
	creation, session, err := s.webAuthn.BeginRegistration(user, registrationOptions...)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceInternal, "Failed to begin registration", "", err)
	}

	// Store session data
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(s.serviceConfig.ChallengeExpiry)
	
	// Serialize session data for storage
	sessionDataBytes, err := json.Marshal(session)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceInternal, "Failed to serialize session data", "", err)
	}

	sessionData := &models.SessionData{
		ID:               sessionID,
		UserID:           req.UserID,
		Challenge:        []byte(session.Challenge),
		ExpiresAt:        expiresAt,
		CreatedAt:        time.Now(),
		UserVerification: models.UserVerificationPreferred,
		// Store the complete session in a field that can handle arbitrary data
		// This would require extending the SessionData model
	}

	if err := s.challengeManager.CreateSession(ctx, sessionData); err != nil {
		return nil, err
	}

	// Also store the complete webauthn session separately for finish registration
	if err := s.sessionStore.StoreWebAuthnSession(ctx, sessionID, sessionDataBytes); err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to store WebAuthn session", "", err)
	}

	// Convert creation options to our models
	creationOptions := &models.PublicKeyCredentialCreationOptions{
		Challenge: []byte(creation.Response.Challenge),
		RP: &models.RelyingPartyEntity{
			ID:   creation.Response.RelyingParty.ID,
			Name: creation.Response.RelyingParty.Name,
		},
		User: &models.UserEntity{
			ID:          []byte(creation.Response.User.ID.(protocol.URLEncodedBase64)),
			Name:        creation.Response.User.Name,
			DisplayName: creation.Response.User.DisplayName,
		},
		PubKeyCredParams: make([]models.PublicKeyCredentialParameters, len(creation.Response.Parameters)),
	}

	// Convert credential parameters
	for i, param := range creation.Response.Parameters {
		creationOptions.PubKeyCredParams[i] = models.PublicKeyCredentialParameters{
			Type: string(param.Type),
			Alg:  models.COSEAlgorithmIdentifier(param.Algorithm),
		}
	}

	// Set optional fields
	if creation.Response.Timeout != 0 {
		timeout := int(creation.Response.Timeout)
		creationOptions.Timeout = &timeout
	}

	// Note: ExcludeCredentials field may not be available in this version
	// Convert exclude credentials if available
	// if len(creation.Response.ExcludeCredentials) > 0 {
	//	creationOptions.ExcludeCredentials = make([]models.CredentialDescriptor, len(creation.Response.ExcludeCredentials))
	//	for i, cred := range creation.Response.ExcludeCredentials {
	//		creationOptions.ExcludeCredentials[i] = models.CredentialDescriptor{
	//			Type: string(cred.Type),
	//			ID:   cred.CredentialID,
	//		}
	//	}
	// }

	// Convert authenticator selection
	if creation.Response.AuthenticatorSelection.AuthenticatorAttachment != "" {
		creationOptions.AuthenticatorSelection = &models.AuthenticatorSelectionCriteria{
			UserVerification: models.UserVerificationRequirement(creation.Response.AuthenticatorSelection.UserVerification),
		}

		if creation.Response.AuthenticatorSelection.AuthenticatorAttachment == protocol.Platform {
			creationOptions.AuthenticatorSelection.AuthenticatorAttachment = models.AuthenticatorAttachmentPlatform
		} else if creation.Response.AuthenticatorSelection.AuthenticatorAttachment == protocol.CrossPlatform {
			creationOptions.AuthenticatorSelection.AuthenticatorAttachment = models.AuthenticatorAttachmentCrossPlatform
		}

		if creation.Response.AuthenticatorSelection.ResidentKey != "" {
			switch creation.Response.AuthenticatorSelection.ResidentKey {
			case protocol.ResidentKeyRequirementRequired:
				creationOptions.AuthenticatorSelection.ResidentKey = models.ResidentKeyRequired
			case protocol.ResidentKeyRequirementPreferred:
				creationOptions.AuthenticatorSelection.ResidentKey = models.ResidentKeyPreferred
			case protocol.ResidentKeyRequirementDiscouraged:
				creationOptions.AuthenticatorSelection.ResidentKey = models.ResidentKeyDiscouraged
			}
		}

		if creation.Response.AuthenticatorSelection.RequireResidentKey != nil {
			creationOptions.AuthenticatorSelection.RequireResidentKey = *creation.Response.AuthenticatorSelection.RequireResidentKey
		}
	}

	// Convert attestation preference
	switch creation.Response.Attestation {
	case protocol.PreferNoAttestation:
		creationOptions.Attestation = models.AttestationConveyanceNone
	case protocol.PreferIndirectAttestation:
		creationOptions.Attestation = models.AttestationConveyanceIndirect
	case protocol.PreferDirectAttestation:
		creationOptions.Attestation = models.AttestationConveyanceDirect
	}

	return &RegistrationStartResponse{
		SessionID:       sessionID,
		CreationOptions: creationOptions,
		ExpiresAt:       expiresAt,
	}, nil
}

// FinishRegistration completes the WebAuthn registration ceremony
func (s *webAuthnService) FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (*RegistrationResult, error) {
	if req == nil || req.SessionID == "" || req.AttestationResponse == nil {
		return &RegistrationResult{
			Success: false,
			Error:   ErrInvalidRequest("Invalid registration finish request"),
		}, nil
	}

	// Get session data
	sessionData, err := s.challengeManager.GetSession(ctx, req.SessionID)
	if err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   ErrSessionNotFound(req.SessionID),
		}, nil
	}

	if sessionData.IsExpired() {
		s.challengeManager.InvalidateSession(ctx, req.SessionID)
		return &RegistrationResult{
			Success: false,
			Error:   ErrSessionExpired(req.SessionID),
		}, nil
	}

	// Get the complete WebAuthn session data
	webauthnSessionBytes, err := s.sessionStore.GetWebAuthnSession(ctx, req.SessionID)
	if err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to get WebAuthn session", "", err),
		}, nil
	}

	var webauthnSession webauthn.SessionData
	if err := json.Unmarshal(webauthnSessionBytes, &webauthnSession); err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceInternal, "Failed to deserialize WebAuthn session", "", err),
		}, nil
	}

	// Get existing credentials for the user
	existingCreds, err := s.credRepo.GetCredentialsByUserID(ctx, sessionData.UserID)
	if err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to get existing credentials", "", err),
		}, nil
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, len(existingCreds))
	for i, cred := range existingCreds {
		webauthnCreds[i] = s.convertToWebAuthnCredential(cred)
	}

	// Create user adapter
	user := &userAdapter{
		userID:      []byte(sessionData.UserID),
		username:    "user", // This should be stored in session or retrieved from user service
		displayName: "user",
		credentials: webauthnCreds,
	}

	// Parse the credential creation response directly using protocol package
	credentialCreationResponse := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   req.AttestationResponse.ID,
				Type: "public-key",
			},
			RawID: req.AttestationResponse.RawID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: req.AttestationResponse.Response.ClientDataJSON,
			},
			AttestationObject: req.AttestationResponse.Response.AttestationObject,
			Transports:        req.AttestationResponse.Response.Transports,
		},
	}
	
	// Parse and verify the credential creation response
	parsedResponse, err := credentialCreationResponse.Parse()
	if err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceValidation, "Failed to parse credential creation response", "", err),
		}, nil
	}
	
	// Verify the credential creation response
	credential, err := s.webAuthn.CreateCredential(user, webauthnSession, parsedResponse)
	if err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceAuthentication, "Registration verification failed", err.Error(), err),
		}, nil
	}

	// Convert and store the credential
	dbCredential := s.convertFromWebAuthnCredential(sessionData.UserID, credential)
	
	// Set transport information if available
	if req.AttestationResponse.Response.Transports != nil {
		transports := make([]models.AuthenticatorTransport, 0, len(req.AttestationResponse.Response.Transports))
		for _, transport := range req.AttestationResponse.Response.Transports {
			switch transport {
			case "usb":
				transports = append(transports, models.TransportUSB)
			case "nfc":
				transports = append(transports, models.TransportNFC)
			case "ble":
				transports = append(transports, models.TransportBLE)
			case "internal":
				transports = append(transports, models.TransportInternal)
			case "hybrid":
				transports = append(transports, models.TransportHybrid)
			}
		}
		dbCredential.Transport = transports
	}

	if err := s.credRepo.CreateCredential(ctx, dbCredential); err != nil {
		return &RegistrationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to store credential", "", err),
		}, nil
	}

	// Clean up sessions
	s.challengeManager.InvalidateSession(ctx, req.SessionID)
	s.sessionStore.DeleteWebAuthnSession(ctx, req.SessionID)

	return &RegistrationResult{
		Success:      true,
		CredentialID: string(dbCredential.CredentialID),
		Credential:   dbCredential,
	}, nil
}

// BeginAuthentication starts the WebAuthn authentication ceremony
func (s *webAuthnService) BeginAuthentication(ctx context.Context, req *AuthenticationStartRequest) (*AuthenticationStartResponse, error) {
	if req == nil {
		return nil, ErrInvalidRequest("Invalid authentication request")
	}

	userID := req.UserID
	if userID == "" && req.UserIdentifier != "" {
		// Look up user by username/identifier to get the actual user ID
		userInfo, err := s.userService.GetUserByUsername(ctx, req.UserIdentifier)
		if err != nil {
			return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get user by identifier", "", err)
		}
		userID = userInfo.ID
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

	// Filter credentials if specific ones are requested
	if len(req.AllowedCredentials) > 0 {
		filteredCreds := make([]*models.WebAuthnCredential, 0)
		for _, cred := range credentials {
			for _, allowedID := range req.AllowedCredentials {
				if string(cred.CredentialID) == string(allowedID) {
					filteredCreds = append(filteredCreds, cred)
					break
				}
			}
		}
		credentials = filteredCreds
	}

	if len(credentials) == 0 {
		return nil, ErrCredentialNotFound("No allowed credentials found for user")
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		webauthnCreds[i] = s.convertToWebAuthnCredential(cred)
	}

	// Create user adapter
	user := &userAdapter{
		userID:      []byte(userID),
		username:    "user", // This should be retrieved from user service
		displayName: "user",
		credentials: webauthnCreds,
	}

	// Set authentication options
	var authOptions []webauthn.LoginOption
	
	if req.Options != nil {
		if req.Options.UserVerification != "" {
			switch req.Options.UserVerification {
			case models.UserVerificationRequired:
				authOptions = append(authOptions, webauthn.WithUserVerification(protocol.VerificationRequired))
			case models.UserVerificationPreferred:
				authOptions = append(authOptions, webauthn.WithUserVerification(protocol.VerificationPreferred))
			case models.UserVerificationDiscouraged:
				authOptions = append(authOptions, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
			}
		}

		if req.Options.Timeout != nil && *req.Options.Timeout > 0 {
			// Note: WebAuthn library handles timeout through credential request options
			// The timeout will be set in the response options automatically
		}
	}

	// Begin authentication with WebAuthn library
	assertion, session, err := s.webAuthn.BeginLogin(user, authOptions...)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceInternal, "Failed to begin authentication", "", err)
	}

	// Store session data
	sessionID := uuid.New().String()
	expiresAt := time.Now().Add(s.serviceConfig.ChallengeExpiry)
	
	// Serialize session data for storage
	sessionDataBytes, err := json.Marshal(session)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceInternal, "Failed to serialize session data", "", err)
	}

	allowedCredentialIDs := make([][]byte, len(credentials))
	for i, cred := range credentials {
		allowedCredentialIDs[i] = cred.CredentialID
	}
	
	sessionData := &models.SessionData{
		ID:                   sessionID,
		UserID:               userID,
		Challenge:            []byte(session.Challenge),
		AllowedCredentialIDs: allowedCredentialIDs,
		ExpiresAt:            expiresAt,
		CreatedAt:            time.Now(),
		UserVerification:     models.UserVerificationPreferred,
	}

	if err := s.challengeManager.CreateSession(ctx, sessionData); err != nil {
		return nil, err
	}

	// Store the complete webauthn session separately
	if err := s.sessionStore.StoreWebAuthnSession(ctx, sessionID, sessionDataBytes); err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to store WebAuthn session", "", err)
	}

	// Convert assertion options to our models
	allowCredentials := make([]models.CredentialDescriptor, len(assertion.Response.AllowedCredentials))
	for i, cred := range assertion.Response.AllowedCredentials {
		transports := make([]models.AuthenticatorTransport, len(cred.Transport))
		for j, transport := range cred.Transport {
			transports[j] = models.AuthenticatorTransport(transport)
		}
		
		allowCredentials[i] = models.CredentialDescriptor{
			Type:       string(cred.Type),
			ID:         cred.CredentialID,
			Transports: transports,
		}
	}

	requestOptions := &models.PublicKeyCredentialRequestOptions{
		Challenge:        []byte(assertion.Response.Challenge),
		RPID:             assertion.Response.RelyingPartyID,
		AllowCredentials: allowCredentials,
		UserVerification: models.UserVerificationRequirement(assertion.Response.UserVerification),
	}

	if assertion.Response.Timeout != 0 {
		timeout := int(assertion.Response.Timeout)
		requestOptions.Timeout = &timeout
	}

	return &AuthenticationStartResponse{
		SessionID:      sessionID,
		RequestOptions: requestOptions,
		ExpiresAt:      expiresAt,
	}, nil
}

// FinishAuthentication completes the WebAuthn authentication ceremony
func (s *webAuthnService) FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (*AuthenticationResult, error) {
	if req == nil || req.SessionID == "" || req.AssertionResponse == nil {
		return &AuthenticationResult{
			Success: false,
			Error:   ErrInvalidRequest("Invalid authentication finish request"),
		}, nil
	}

	// Get session data
	sessionData, err := s.challengeManager.GetSession(ctx, req.SessionID)
	if err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   ErrSessionNotFound(req.SessionID),
		}, nil
	}

	if sessionData.IsExpired() {
		s.challengeManager.InvalidateSession(ctx, req.SessionID)
		return &AuthenticationResult{
			Success: false,
			Error:   ErrSessionExpired(req.SessionID),
		}, nil
	}

	// Get the complete WebAuthn session data
	webauthnSessionBytes, err := s.sessionStore.GetWebAuthnSession(ctx, req.SessionID)
	if err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to get WebAuthn session", "", err),
		}, nil
	}

	var webauthnSession webauthn.SessionData
	if err := json.Unmarshal(webauthnSessionBytes, &webauthnSession); err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceInternal, "Failed to deserialize WebAuthn session", "", err),
		}, nil
	}

	// Get user credentials
	credentials, err := s.credRepo.GetCredentialsByUserID(ctx, sessionData.UserID)
	if err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceDependency, "Failed to get user credentials", "", err),
		}, nil
	}

	// Convert to WebAuthn credentials
	webauthnCreds := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		webauthnCreds[i] = s.convertToWebAuthnCredential(cred)
	}

	// Create user adapter
	user := &userAdapter{
		userID:      []byte(sessionData.UserID),
		username:    "user", // This should be retrieved from user service
		displayName: "user",
		credentials: webauthnCreds,
	}

	// Parse the credential request response directly using protocol package
	credentialRequestResponse := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   req.AssertionResponse.ID,
				Type: "public-key",
			},
			RawID: req.AssertionResponse.RawID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: req.AssertionResponse.Response.ClientDataJSON,
			},
			AuthenticatorData: req.AssertionResponse.Response.AuthenticatorData,
			Signature:         req.AssertionResponse.Response.Signature,
			UserHandle:        req.AssertionResponse.Response.UserHandle,
		},
	}
	
	// Parse and verify the credential assertion response
	parsedResponse, err := credentialRequestResponse.Parse()
	if err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceValidation, "Failed to parse credential assertion response", "", err),
		}, nil
	}
	
	// Verify the credential assertion response  
	credential, err := s.webAuthn.ValidateLogin(user, webauthnSession, parsedResponse)
	if err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   NewServiceErrorWithCause(ErrServiceAuthentication, "Authentication verification failed", err.Error(), err),
		}, nil
	}

	// Find the credential in our database
	var dbCredential *models.WebAuthnCredential
	for _, cred := range credentials {
		if string(cred.CredentialID) == string(credential.ID) {
			dbCredential = cred
			break
		}
	}

	if dbCredential == nil {
		return &AuthenticationResult{
			Success: false,
			Error:   ErrCredentialNotFound(string(credential.ID)),
		}, nil
	}

	// Validate credential usage for security
	if err := s.ValidateCredentialUsage(ctx, credential.ID, credential.Authenticator.SignCount); err != nil {
		return &AuthenticationResult{
			Success: false,
			Error:   err.(*ServiceError),
			Warnings: []string{"Potential security issue detected"},
		}, nil
	}

	// Update credential with new sign count
	dbCredential.SignCount = credential.Authenticator.SignCount
	dbCredential.UpdatedAt = time.Now()
	
	if err := s.credRepo.UpdateCredential(ctx, dbCredential); err != nil {
		// Don't fail authentication for update error, but log warning
		return &AuthenticationResult{
			Success:            true,
			UserID:             sessionData.UserID,
			CredentialID:       string(credential.ID),
			SignCount:          credential.Authenticator.SignCount,
			AuthenticationTime: time.Now(),
			Warnings:           []string{"Failed to update credential sign count"},
		}, nil
	}

	// Clean up sessions
	s.challengeManager.InvalidateSession(ctx, req.SessionID)
	s.sessionStore.DeleteWebAuthnSession(ctx, req.SessionID)

	return &AuthenticationResult{
		Success:            true,
		UserID:             sessionData.UserID,
		CredentialID:       string(credential.ID),
		SignCount:          credential.Authenticator.SignCount,
		AuthenticationTime: time.Now(),
	}, nil
}

// Implement remaining interface methods from simple_service.go
func (s *webAuthnService) GetUserCredentials(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	if userID == "" {
		return nil, ErrInvalidRequest("User ID is required")
	}

	credentials, err := s.credRepo.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credentials", "", err)
	}

	return credentials, nil
}

func (s *webAuthnService) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
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

func (s *webAuthnService) DeleteCredential(ctx context.Context, userID string, credentialID []byte) error {
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

func (s *webAuthnService) GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error) {
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

func (s *webAuthnService) CleanupExpiredData(ctx context.Context) error {
	// Cleanup expired sessions
	if err := s.challengeManager.CleanupExpiredSessions(ctx); err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to cleanup expired sessions", "", err)
	}

	// Cleanup old credentials if configured
	if s.serviceConfig.CredentialTimeout > 0 {
		retentionPeriod := 365 * 24 * time.Hour // 1 year default
		if err := s.credRepo.CleanupExpiredCredentials(ctx, retentionPeriod); err != nil {
			return NewServiceErrorWithCause(ErrServiceDependency, "Failed to cleanup expired credentials", "", err)
		}
	}

	return nil
}

func (s *webAuthnService) ValidateCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error {
	if !s.serviceConfig.SignCountValidation {
		return nil
	}

	// Get current credential
	credential, err := s.credRepo.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return NewServiceErrorWithCause(ErrServiceDependency, "Failed to get credential for validation", "", err)
	}

	// Check for sign count regression (possible cloning)
	if signCount <= credential.SignCount && credential.SignCount > 0 {
		if s.serviceConfig.CloneDetection {
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