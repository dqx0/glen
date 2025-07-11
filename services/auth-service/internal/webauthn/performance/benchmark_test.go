package performance

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/repository"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// BenchmarkCredentialCreation benchmarks the credential creation process
func BenchmarkCredentialCreation(b *testing.B) {
	// Setup in-memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlite3")
	
	// Create table
	_, err = sqlxDB.Exec(`
		CREATE TABLE webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT NOT NULL,
			transport TEXT NOT NULL,
			flags TEXT NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		b.Fatal(err)
	}

	// Create repository
	config := &repository.RepositoryConfig{}
	repo := repository.NewPostgreSQLWebAuthnRepository(sqlxDB, config)

	// Reset timer after setup
	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		credential := &models.WebAuthnCredential{
			ID:              uuid.New().String(),
			UserID:          uuid.New().String(),
			CredentialID:    []byte(uuid.New().String()),
			PublicKey:       []byte("test-public-key"),
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

		err := repo.CreateCredential(context.Background(), credential)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialRetrieval benchmarks credential retrieval
func BenchmarkCredentialRetrieval(b *testing.B) {
	// Setup
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlite3")
	
	// Create table
	_, err = sqlxDB.Exec(`
		CREATE TABLE webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT NOT NULL,
			transport TEXT NOT NULL,
			flags TEXT NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		b.Fatal(err)
	}

	config := &repository.RepositoryConfig{}
	repo := repository.NewPostgreSQLWebAuthnRepository(sqlxDB, config)

	// Pre-populate with test data
	userID := uuid.New().String()
	for i := 0; i < 100; i++ {
		credential := &models.WebAuthnCredential{
			ID:              uuid.New().String(),
			UserID:          userID,
			CredentialID:    []byte(uuid.New().String()),
			PublicKey:       []byte("test-public-key"),
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
		repo.CreateCredential(context.Background(), credential)
	}

	b.ResetTimer()

	// Benchmark retrieval
	for i := 0; i < b.N; i++ {
		_, err := repo.GetCredentialsByUserID(context.Background(), userID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJWTGeneration benchmarks JWT token generation
func BenchmarkJWTGeneration(b *testing.B) {
	config := middleware.DefaultJWTConfig()
	userID := uuid.New().String()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := middleware.GenerateToken(config, userID, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJWTValidation benchmarks JWT token validation
func BenchmarkJWTValidation(b *testing.B) {
	config := middleware.DefaultJWTConfig()
	userID := uuid.New().String()

	// Pre-generate token
	token, err := middleware.GenerateToken(config, userID, false)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := middleware.ValidateToken(config, token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConcurrentCredentialCreation benchmarks concurrent credential creation
func BenchmarkConcurrentCredentialCreation(b *testing.B) {
	// Setup
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	sqlxDB := sqlx.NewDb(db, "sqlite3")
	
	// Create table
	_, err = sqlxDB.Exec(`
		CREATE TABLE webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT NOT NULL,
			transport TEXT NOT NULL,
			flags TEXT NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		b.Fatal(err)
	}

	config := &repository.RepositoryConfig{}
	repo := repository.NewPostgreSQLWebAuthnRepository(sqlxDB, config)

	b.ResetTimer()

	// Run concurrent benchmark
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			credential := &models.WebAuthnCredential{
				ID:              uuid.New().String(),
				UserID:          uuid.New().String(),
				CredentialID:    []byte(uuid.New().String()),
				PublicKey:       []byte("test-public-key"),
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

			err := repo.CreateCredential(context.Background(), credential)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkServiceRegistrationFlow benchmarks the complete registration service flow
func BenchmarkServiceRegistrationFlow(b *testing.B) {
	// Setup service with mock dependencies
	mockSessionStore := &mockSessionStore{
		sessions: make(map[string]*models.SessionData),
	}

	// Create mock repository
	mockRepo := &mockRepository{
		credentials: make(map[string]*models.WebAuthnCredential),
	}

	config := &service.WebAuthnConfig{
		RPID:             "localhost",
		RPName:           "Test Service",
		AllowedOrigins:   []string{"https://localhost"},
		ChallengeLength:  32,
		SessionTimeout:   5 * time.Minute,
		ChallengeExpiry:  2 * time.Minute,
	}

	webauthnService, err := service.NewSimpleWebAuthnService(mockRepo, mockSessionStore, config)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		userID := uuid.New().String()
		
		// Start registration
		startReq := &service.RegistrationStartRequest{
			UserID:      userID,
			Username:    "testuser",
			DisplayName: "Test User",
		}

		startResp, err := webauthnService.BeginRegistration(context.Background(), startReq)
		if err != nil {
			b.Fatal(err)
		}

		// Finish registration (simplified for benchmark)
		finishReq := &service.RegistrationFinishRequest{
			SessionID: startResp.SessionID,
			AttestationResponse: &models.AuthenticatorAttestationResponse{
				ID:    "test-credential",
				Type:  "public-key",
				RawID: []byte("test-credential"),
				Response: &models.AuthenticatorAttestationResponseData{
					ClientDataJSON:    []byte(`{"type":"webauthn.create","challenge":"test","origin":"https://localhost"}`),
					AttestationObject: []byte("test-attestation"),
				},
			},
		}

		_, err = webauthnService.FinishRegistration(context.Background(), finishReq)
		if err != nil {
			// Expected to fail in simplified benchmark, but measure the attempt
		}
	}
}

// Mock implementations for benchmarking

type mockSessionStore struct {
	sessions map[string]*models.SessionData
}

func (m *mockSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	if session, exists := m.sessions[sessionID]; exists {
		return session, nil
	}
	return nil, repository.ErrSessionNotFound
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	return nil
}

func (m *mockSessionStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	return len(m.sessions), nil
}

func (m *mockSessionStore) GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error) {
	return nil, nil
}

func (m *mockSessionStore) ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error) {
	return true, nil
}

func (m *mockSessionStore) ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error {
	return nil
}

type mockRepository struct {
	credentials map[string]*models.WebAuthnCredential
}

func (m *mockRepository) CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	m.credentials[credential.ID] = credential
	return nil
}

func (m *mockRepository) GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	var creds []*models.WebAuthnCredential
	for _, cred := range m.credentials {
		if cred.UserID == userID {
			creds = append(creds, cred)
		}
	}
	return creds, nil
}

func (m *mockRepository) GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	for _, cred := range m.credentials {
		if string(cred.CredentialID) == string(credentialID) {
			return cred, nil
		}
	}
	return nil, repository.ErrCredentialNotFound
}

func (m *mockRepository) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	m.credentials[credential.ID] = credential
	return nil
}

func (m *mockRepository) DeleteCredential(ctx context.Context, credentialID []byte) error {
	for id, cred := range m.credentials {
		if string(cred.CredentialID) == string(credentialID) {
			delete(m.credentials, id)
			return nil
		}
	}
	return repository.ErrCredentialNotFound
}

func (m *mockRepository) GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	return m.GetCredentialsByUserID(ctx, userID)
}

func (m *mockRepository) UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return nil
}

func (m *mockRepository) UpdateCredentialLastUsed(ctx context.Context, credentialID []byte, lastUsed time.Time) error {
	return nil
}

func (m *mockRepository) GetCredentialCount(ctx context.Context, userID string) (int, error) {
	count := 0
	for _, cred := range m.credentials {
		if cred.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (m *mockRepository) GetCredentialsByTransport(ctx context.Context, transport models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	return nil, nil
}

func (m *mockRepository) CleanupExpiredCredentials(ctx context.Context, retentionPeriod time.Duration) error {
	return nil
}

func (m *mockRepository) GetCredentialStatistics(ctx context.Context) (*repository.CredentialStatistics, error) {
	return &repository.CredentialStatistics{
		TotalCredentials: len(m.credentials),
	}, nil
}