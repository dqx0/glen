package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/user-service/internal/models"
	"github.com/dqx0/glen/user-service/internal/service"
)

// MockUserService は UserService のモック
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Register(ctx context.Context, username, email, password string) (*models.User, error) {
	args := m.Called(ctx, username, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) Login(ctx context.Context, username, password string) (*models.User, error) {
	args := m.Called(ctx, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) UpdatePassword(ctx context.Context, username, newPassword string) error {
	args := m.Called(ctx, username, newPassword)
	return args.Error(0)
}

func (m *MockUserService) VerifyEmail(ctx context.Context, username string) error {
	args := m.Called(ctx, username)
	return args.Error(0)
}

func TestUserHandler_Register(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockUserService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "successful registration",
			requestBody: map[string]string{
				"username": "testuser",
				"email":    "test@example.com",
				"password": "password123",
			},
			setupMock: func(m *MockUserService) {
				user, _ := models.NewUser("testuser", "test@example.com", "password123")
				m.On("Register", mock.Anything, "testuser", "test@example.com", "password123").Return(user, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]interface{}{
				"success": true,
				"user": map[string]interface{}{
					"username": "testuser",
					"email":    "test@example.com",
					"is_active": true,
				},
			},
		},
		{
			name: "registration with username only (WebAuthn)",
			requestBody: map[string]string{
				"username": "testuser",
			},
			setupMock: func(m *MockUserService) {
				user, _ := models.NewUser("testuser", "", "")
				m.On("Register", mock.Anything, "testuser", "", "").Return(user, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]interface{}{
				"success": true,
				"user": map[string]interface{}{
					"username": "testuser",
					"email":    "",
					"is_active": true,
				},
			},
		},
		{
			name: "registration fails - username exists",
			requestBody: map[string]string{
				"username": "testuser",
				"email":    "test@example.com",
				"password": "password123",
			},
			setupMock: func(m *MockUserService) {
				m.On("Register", mock.Anything, "testuser", "test@example.com", "password123").Return(nil, service.ErrUsernameExists)
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]interface{}{
				"success": false,
				"error":   "username already exists",
			},
		},
		{
			name: "registration fails - invalid JSON",
			requestBody: "invalid json",
			setupMock: func(m *MockUserService) {
				// モックは呼ばれない
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"error":   "invalid request body",
			},
		},
		{
			name: "registration fails - missing username",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			setupMock: func(m *MockUserService) {
				// モックは呼ばれない
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"error":   "username is required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.setupMock(mockService)
			
			handler := NewUserHandler(mockService)
			
			// リクエストボディを作成
			var bodyBytes []byte
			if str, ok := tt.requestBody.(string); ok {
				bodyBytes = []byte(str)
			} else {
				bodyBytes, _ = json.Marshal(tt.requestBody)
			}
			
			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			
			handler.Register(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			// レスポンスの主要フィールドを検証
			assert.Equal(t, tt.expectedBody["success"], response["success"])
			if tt.expectedBody["error"] != nil {
				assert.Equal(t, tt.expectedBody["error"], response["error"])
			}
			if tt.expectedBody["user"] != nil {
				userResponse, ok := response["user"].(map[string]interface{})
				require.True(t, ok)
				expectedUser := tt.expectedBody["user"].(map[string]interface{})
				assert.Equal(t, expectedUser["username"], userResponse["username"])
				assert.Equal(t, expectedUser["email"], userResponse["email"])
				assert.Equal(t, expectedUser["is_active"], userResponse["is_active"])
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestUserHandler_Login(t *testing.T) {
	testUser, _ := models.NewUser("testuser", "test@example.com", "password123")
	
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockUserService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "successful login",
			requestBody: map[string]string{
				"username": "testuser",
				"password": "password123",
			},
			setupMock: func(m *MockUserService) {
				m.On("Login", mock.Anything, "testuser", "password123").Return(testUser, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"user": map[string]interface{}{
					"username": "testuser",
					"email":    "test@example.com",
					"is_active": true,
				},
			},
		},
		{
			name: "login fails - invalid credentials",
			requestBody: map[string]string{
				"username": "testuser",
				"password": "wrongpassword",
			},
			setupMock: func(m *MockUserService) {
				m.On("Login", mock.Anything, "testuser", "wrongpassword").Return(nil, service.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"success": false,
				"error":   "invalid credentials",
			},
		},
		{
			name: "login fails - missing fields",
			requestBody: map[string]string{
				"username": "testuser",
			},
			setupMock: func(m *MockUserService) {
				// モックは呼ばれない
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"error":   "username and password are required",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.setupMock(mockService)
			
			handler := NewUserHandler(mockService)
			
			bodyBytes, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			
			handler.Login(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedBody["success"], response["success"])
			if tt.expectedBody["error"] != nil {
				assert.Equal(t, tt.expectedBody["error"], response["error"])
			}
			
			mockService.AssertExpectations(t)
		})
	}
}