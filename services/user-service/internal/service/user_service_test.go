package service

import (
	"context"
	"testing"

	"github.com/dqx0/glen/user-service/internal/models"
	"github.com/dqx0/glen/user-service/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserRepository は UserRepository のモック
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func TestUserService_Register(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		email       string
		password    string
		setupMock   func(*MockUserRepository)
		wantErr     bool
		expectedErr string
	}{
		{
			name:     "successful registration with password",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(nil, repository.ErrUserNotFound)
				m.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, repository.ErrUserNotFound)
				m.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
			},
			wantErr: false,
		},
		{
			name:     "successful registration without password (WebAuthn only)",
			username: "testuser",
			email:    "",
			password: "",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(nil, repository.ErrUserNotFound)
				m.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
			},
			wantErr: false,
		},
		{
			name:     "registration fails - username already exists",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				existingUser, _ := models.NewUser("testuser", "existing@example.com", "password")
				m.On("GetByUsername", mock.Anything, "testuser").Return(existingUser, nil)
			},
			wantErr:     true,
			expectedErr: "username already exists",
		},
		{
			name:     "registration fails - email already exists",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(nil, repository.ErrUserNotFound)
				existingUser, _ := models.NewUser("existinguser", "test@example.com", "password")
				m.On("GetByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)
			},
			wantErr:     true,
			expectedErr: "email already exists",
		},
		{
			name:     "registration fails - invalid username",
			username: "",
			email:    "test@example.com",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "").Return(nil, repository.ErrUserNotFound)
				m.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, repository.ErrUserNotFound)
			},
			wantErr:     true,
			expectedErr: "invalid username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			service := NewUserService(mockRepo)

			user, err := service.Register(context.Background(), tt.username, tt.email, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, tt.username, user.Username)
				assert.Equal(t, tt.email, user.Email)
				assert.True(t, user.IsActive())
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_Login(t *testing.T) {
	// テスト用ユーザーを作成
	testUser, err := models.NewUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	tests := []struct {
		name        string
		username    string
		password    string
		setupMock   func(*MockUserRepository)
		wantErr     bool
		expectedErr string
	}{
		{
			name:     "successful login",
			username: "testuser",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			wantErr: false,
		},
		{
			name:     "login fails - user not found",
			username: "nonexistent",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "nonexistent").Return(nil, repository.ErrUserNotFound)
			},
			wantErr:     true,
			expectedErr: "invalid credentials",
		},
		{
			name:     "login fails - wrong password",
			username: "testuser",
			password: "wrongpassword",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			wantErr:     true,
			expectedErr: "invalid credentials",
		},
		{
			name:     "login fails - no password set",
			username: "testuser",
			password: "password123",
			setupMock: func(m *MockUserRepository) {
				noPasswordUser, _ := models.NewUser("testuser", "test@example.com", "")
				m.On("GetByUsername", mock.Anything, "testuser").Return(noPasswordUser, nil)
			},
			wantErr:     true,
			expectedErr: "password authentication not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			service := NewUserService(mockRepo)

			user, err := service.Login(context.Background(), tt.username, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, tt.username, user.Username)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_GetUser(t *testing.T) {
	testUser, err := models.NewUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	tests := []struct {
		name        string
		username    string
		setupMock   func(*MockUserRepository)
		wantErr     bool
		expectedErr string
	}{
		{
			name:     "get user successfully",
			username: "testuser",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			wantErr: false,
		},
		{
			name:     "user not found",
			username: "nonexistent",
			setupMock: func(m *MockUserRepository) {
				m.On("GetByUsername", mock.Anything, "nonexistent").Return(nil, repository.ErrUserNotFound)
			},
			wantErr:     true,
			expectedErr: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			tt.setupMock(mockRepo)

			service := NewUserService(mockRepo)

			user, err := service.GetUser(context.Background(), tt.username)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				assert.Equal(t, tt.username, user.Username)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
