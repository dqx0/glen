package testutil

//go:generate mockgen -source=../webauthn/repository/interfaces.go -destination=mocks/repository_mock.go -package=mocks
//go:generate mockgen -source=../webauthn/service/interfaces.go -destination=mocks/service_mock.go -package=mocks
//go:generate mockgen -source=../webauthn/security/interfaces.go -destination=mocks/security_mock.go -package=mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
)

// MockWebAuthnRepository is a mock implementation of WebAuthnRepository
type MockWebAuthnRepository struct {
	mock.Mock
}

func (m *MockWebAuthnRepository) CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *MockWebAuthnRepository) GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

func (m *MockWebAuthnRepository) GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	args := m.Called(ctx, credentialID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WebAuthnCredential), args.Error(1)
}

func (m *MockWebAuthnRepository) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *MockWebAuthnRepository) DeleteCredential(ctx context.Context, credentialID []byte) error {
	args := m.Called(ctx, credentialID)
	return args.Error(0)
}

func (m *MockWebAuthnRepository) GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, userID, transports)
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

// MockSessionStore is a mock implementation of SessionStore
type MockSessionStore struct {
	mock.Mock
}

func (m *MockSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SessionData), args.Error(1)
}

func (m *MockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockWebAuthnService is a mock implementation of WebAuthnService
type MockWebAuthnService struct {
	mock.Mock
}

func (m *MockWebAuthnService) BeginRegistration(ctx context.Context, req *models.RegistrationStartRequest) (*models.RegistrationStartResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RegistrationStartResponse), args.Error(1)
}

func (m *MockWebAuthnService) FinishRegistration(ctx context.Context, req *models.RegistrationFinishRequest) (*models.RegistrationResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RegistrationResult), args.Error(1)
}

func (m *MockWebAuthnService) BeginAuthentication(ctx context.Context, req *models.AuthenticationStartRequest) (*models.AuthenticationStartResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuthenticationStartResponse), args.Error(1)
}

func (m *MockWebAuthnService) FinishAuthentication(ctx context.Context, req *models.AuthenticationFinishRequest) (*models.AuthenticationResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.AuthenticationResult), args.Error(1)
}

// MockOriginValidator is a mock implementation of OriginValidator
type MockOriginValidator struct {
	mock.Mock
}

func (m *MockOriginValidator) ValidateOrigin(ctx context.Context, origin string) error {
	args := m.Called(ctx, origin)
	return args.Error(0)
}

func (m *MockOriginValidator) IsAllowedOrigin(origin string) bool {
	args := m.Called(origin)
	return args.Bool(0)
}

func (m *MockOriginValidator) GetAllowedOrigins() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// MockRateLimiter is a mock implementation of RateLimiter
type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) IsAllowed(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockRateLimiter) GetLimit(key string) (int, time.Duration) {
	args := m.Called(key)
	return args.Int(0), args.Get(1).(time.Duration)
}

func (m *MockRateLimiter) Reset(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

// MockLogger is a mock implementation of Logger
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(ctx context.Context, msg string, fields map[string]interface{}) {
	m.Called(ctx, msg, fields)
}

func (m *MockLogger) Info(ctx context.Context, msg string, fields map[string]interface{}) {
	m.Called(ctx, msg, fields)
}

func (m *MockLogger) Warn(ctx context.Context, msg string, fields map[string]interface{}) {
	m.Called(ctx, msg, fields)
}

func (m *MockLogger) Error(ctx context.Context, msg string, err error, fields map[string]interface{}) {
	m.Called(ctx, msg, err, fields)
}

func (m *MockLogger) Fatal(ctx context.Context, msg string, err error, fields map[string]interface{}) {
	m.Called(ctx, msg, err, fields)
}

// MockMetricsCollector is a mock implementation of MetricsCollector
type MockMetricsCollector struct {
	mock.Mock
}

func (m *MockMetricsCollector) IncrementCounter(name string, labels map[string]string) {
	m.Called(name, labels)
}

func (m *MockMetricsCollector) RecordHistogram(name string, value float64, labels map[string]string) {
	m.Called(name, value, labels)
}

func (m *MockMetricsCollector) SetGauge(name string, value float64, labels map[string]string) {
	m.Called(name, value, labels)
}

func (m *MockMetricsCollector) RecordDuration(name string, duration time.Duration, labels map[string]string) {
	m.Called(name, duration, labels)
}