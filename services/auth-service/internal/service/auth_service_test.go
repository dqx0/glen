package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/auth-service/internal/models"
)

// MockTokenRepository はTokenRepositoryのモック
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Create(ctx context.Context, token *models.Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenRepository) GetByID(ctx context.Context, id string) (*models.Token, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) GetByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Token), args.Error(1)
}

func (m *MockTokenRepository) GetByTypeAndUserID(ctx context.Context, tokenType, userID string) ([]*models.Token, error) {
	args := m.Called(ctx, tokenType, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Token), args.Error(1)
}

func (m *MockTokenRepository) Update(ctx context.Context, token *models.Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockTokenRepository) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Token, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

// MockJWTService はJWTServiceのモック
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateAccessToken(userID, username string, scopes []string) (string, string, error) {
	args := m.Called(userID, username, scopes)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockJWTService) ValidateToken(tokenString string) (*Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

func TestAuthService_Login(t *testing.T) {
	mockTokenRepo := new(MockTokenRepository)
	mockJWTService := new(MockJWTService)
	
	service := &AuthService{
		tokenRepo:  mockTokenRepo,
		jwtService: mockJWTService,
	}

	t.Run("successful login", func(t *testing.T) {
		userID := "user-123"
		username := "testuser"
		sessionName := "web-session"
		scopes := []string{"user:read", "user:write"}

		// JWTトークン生成をモック
		expectedAccessToken := "jwt.access.token"
		expectedJWTID := "jwt-id-123"
		mockJWTService.On("GenerateAccessToken", userID, username, scopes).Return(expectedAccessToken, expectedJWTID, nil)

		// Refresh token作成をモック
		mockTokenRepo.On("Create", mock.Anything, mock.MatchedBy(func(token *models.Token) bool {
			return token.UserID == userID && token.Type == models.TokenTypeRefresh
		})).Return(nil)

		response, err := service.Login(context.Background(), userID, username, sessionName, scopes)
		
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, expectedAccessToken, response.AccessToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.Equal(t, int64(900), response.ExpiresIn) // 15分 = 900秒
		assert.NotEmpty(t, response.RefreshToken)

		mockJWTService.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		response, err := service.Login(context.Background(), "", "testuser", "session", []string{"user:read"})
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrInvalidUserID, err)
	})

	t.Run("invalid username", func(t *testing.T) {
		response, err := service.Login(context.Background(), "user-123", "", "session", []string{"user:read"})
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrInvalidUsername, err)
	})

	t.Run("empty scopes", func(t *testing.T) {
		response, err := service.Login(context.Background(), "user-123", "testuser", "session", []string{})
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrEmptyScopes, err)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	mockTokenRepo := new(MockTokenRepository)
	mockJWTService := new(MockJWTService)
	
	service := &AuthService{
		tokenRepo:  mockTokenRepo,
		jwtService: mockJWTService,
	}

	t.Run("successful token refresh", func(t *testing.T) {
		refreshTokenValue := "refresh-token-value"
		userID := "user-123"
		username := "testuser"
		scopes := []string{"user:read", "user:write"}

		// 既存のRefresh tokenを取得
		existingToken, err := models.NewRefreshToken(userID, "session", scopes)
		require.NoError(t, err)
		
		// Token hashを直接設定（テスト用）
		existingToken.TokenHash = "hashed-refresh-token"

		mockTokenRepo.On("GetByTokenHash", mock.Anything, mock.AnythingOfType("string")).Return(existingToken, nil)

		// JWTトークン生成をモック
		expectedAccessToken := "new.jwt.access.token"
		expectedJWTID := "new-jwt-id-123"
		mockJWTService.On("GenerateAccessToken", userID, username, scopes).Return(expectedAccessToken, expectedJWTID, nil)

		// Last used time更新をモック
		mockTokenRepo.On("Update", mock.Anything, mock.MatchedBy(func(token *models.Token) bool {
			return token.ID == existingToken.ID
		})).Return(nil)

		response, err := service.RefreshToken(context.Background(), refreshTokenValue, username)
		
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, expectedAccessToken, response.AccessToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.Equal(t, int64(900), response.ExpiresIn)

		mockJWTService.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		refreshTokenValue := "invalid-token"
		
		mockTokenRepo.On("GetByTokenHash", mock.Anything, mock.AnythingOfType("string")).Return(nil, ErrTokenNotFound)

		response, err := service.RefreshToken(context.Background(), refreshTokenValue, "testuser")
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrInvalidRefreshToken, err)
	})

	t.Run("expired token", func(t *testing.T) {
		refreshTokenValue := "expired-token-value"
		userID := "user-123"
		
		// 期限切れのRefresh tokenを作成
		expiredToken, err := models.NewRefreshToken(userID, "session", []string{"user:read"})
		require.NoError(t, err)
		expiredToken.ExpiresAt = time.Now().Add(-time.Hour) // 1時間前に期限切れ

		mockTokenRepo.On("GetByTokenHash", mock.Anything, mock.AnythingOfType("string")).Return(expiredToken, nil)

		response, err := service.RefreshToken(context.Background(), refreshTokenValue, "testuser")
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrTokenExpired, err)
	})
}

func TestAuthService_CreateAPIKey(t *testing.T) {
	mockTokenRepo := new(MockTokenRepository)
	mockJWTService := new(MockJWTService)
	
	service := &AuthService{
		tokenRepo:  mockTokenRepo,
		jwtService: mockJWTService,
	}

	t.Run("successful API key creation", func(t *testing.T) {
		userID := "user-123"
		keyName := "production-api"
		scopes := []string{"api:read", "api:write"}

		mockTokenRepo.On("Create", mock.Anything, mock.MatchedBy(func(token *models.Token) bool {
			return token.UserID == userID && token.Type == models.TokenTypeAPIKey && token.Name == keyName
		})).Return(nil)

		response, err := service.CreateAPIKey(context.Background(), userID, keyName, scopes)
		
		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, keyName, response.Name)
		assert.Equal(t, scopes, response.Scopes)
		assert.NotEmpty(t, response.Token)
		assert.NotEmpty(t, response.ID)
		assert.False(t, response.CreatedAt.IsZero())

		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		response, err := service.CreateAPIKey(context.Background(), "", "api-key", []string{"api:read"})
		
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Equal(t, ErrInvalidUserID, err)
	})
}

func TestAuthService_RevokeToken(t *testing.T) {
	mockTokenRepo := new(MockTokenRepository)
	mockJWTService := new(MockJWTService)
	
	service := &AuthService{
		tokenRepo:  mockTokenRepo,
		jwtService: mockJWTService,
	}

	t.Run("successful token revocation", func(t *testing.T) {
		tokenID := "token-123"
		userID := "user-123"

		// 既存トークンの取得をモック
		existingToken, err := models.NewRefreshToken(userID, "session", []string{"user:read"})
		require.NoError(t, err)
		existingToken.ID = tokenID

		mockTokenRepo.On("GetByID", mock.Anything, tokenID).Return(existingToken, nil)
		mockTokenRepo.On("Delete", mock.Anything, tokenID).Return(nil)

		err = service.RevokeToken(context.Background(), tokenID, userID)
		
		require.NoError(t, err)

		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		tokenID := "nonexistent-token"
		userID := "user-123"

		mockTokenRepo.On("GetByID", mock.Anything, tokenID).Return(nil, ErrTokenNotFound)

		err := service.RevokeToken(context.Background(), tokenID, userID)
		
		assert.Error(t, err)
		assert.Equal(t, ErrTokenNotFound, err)
	})

	t.Run("unauthorized - different user", func(t *testing.T) {
		tokenID := "token-123"
		userID := "user-123"
		differentUserID := "user-456"

		// 別のユーザーのトークン
		existingToken, err := models.NewRefreshToken(differentUserID, "session", []string{"user:read"})
		require.NoError(t, err)
		existingToken.ID = tokenID

		mockTokenRepo.On("GetByID", mock.Anything, tokenID).Return(existingToken, nil)

		err = service.RevokeToken(context.Background(), tokenID, userID)
		
		assert.Error(t, err)
		assert.Equal(t, ErrUnauthorized, err)
	})
}