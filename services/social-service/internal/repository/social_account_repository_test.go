package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/social-service/internal/models"
)

func TestSocialAccountRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSocialAccountRepository(db)

	tests := []struct {
		name    string
		account *models.SocialAccount
		wantErr bool
	}{
		{
			name: "create Google account successfully",
			account: &models.SocialAccount{
				ID:          "account-123",
				UserID:      "user-123", 
				Provider:    models.ProviderGoogle,
				ProviderID:  "google-123456",
				Email:       "user@example.com",
				DisplayName: "Test User",
				ProfileData: map[string]interface{}{
					"picture": "https://example.com/avatar.jpg",
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "create GitHub account successfully",
			account: &models.SocialAccount{
				ID:          "account-456",
				UserID:      "user-456",
				Provider:    models.ProviderGitHub,
				ProviderID:  "github-789",
				Email:       "dev@example.com",
				DisplayName: "Developer",
				ProfileData: map[string]interface{}{
					"login": "devuser",
					"public_repos": 25,
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.Create(context.Background(), tt.account)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				
				// 作成された内容を確認
				created, err := repo.GetByID(context.Background(), tt.account.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.account.UserID, created.UserID)
				assert.Equal(t, tt.account.Provider, created.Provider)
				assert.Equal(t, tt.account.ProviderID, created.ProviderID)
			}
		})
	}
}

func TestSocialAccountRepository_GetByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSocialAccountRepository(db)

	// テストデータ作成
	account1 := &models.SocialAccount{
		ID:          "account-1",
		UserID:      "user-123",
		Provider:    models.ProviderGoogle,
		ProviderID:  "google-123",
		Email:       "user@example.com",
		DisplayName: "User One",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	account2 := &models.SocialAccount{
		ID:          "account-2",
		UserID:      "user-123",
		Provider:    models.ProviderGitHub,
		ProviderID:  "github-456",
		Email:       "user@example.com",
		DisplayName: "User One",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	require.NoError(t, repo.Create(context.Background(), account1))
	require.NoError(t, repo.Create(context.Background(), account2))

	tests := []struct {
		name           string
		userID         string
		expectedCount  int
	}{
		{
			name:          "get accounts by user ID",
			userID:        "user-123",
			expectedCount: 2,
		},
		{
			name:          "get accounts by non-existent user",
			userID:        "user-999",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accounts, err := repo.GetByUserID(context.Background(), tt.userID)
			require.NoError(t, err)
			assert.Len(t, accounts, tt.expectedCount)
		})
	}
}

func TestSocialAccountRepository_GetByProviderAndProviderID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSocialAccountRepository(db)

	// テストデータ作成
	account := &models.SocialAccount{
		ID:          "account-123",
		UserID:      "user-123",
		Provider:    models.ProviderGoogle,
		ProviderID:  "google-unique-id",
		Email:       "user@example.com",
		DisplayName: "Test User",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	require.NoError(t, repo.Create(context.Background(), account))

	tests := []struct {
		name       string
		provider   string
		providerID string
		expectFind bool
	}{
		{
			name:       "find existing account",
			provider:   models.ProviderGoogle,
			providerID: "google-unique-id",
			expectFind: true,
		},
		{
			name:       "account not found",
			provider:   models.ProviderGoogle,
			providerID: "google-nonexistent",
			expectFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := repo.GetByProviderAndProviderID(context.Background(), tt.provider, tt.providerID)
			
			if tt.expectFind {
				require.NoError(t, err)
				assert.Equal(t, account.UserID, found.UserID)
				assert.Equal(t, account.Provider, found.Provider)
			} else {
				assert.Error(t, err)
				assert.True(t, IsErrSocialAccountNotFound(err))
			}
		})
	}
}

func TestSocialAccountRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSocialAccountRepository(db)

	// テストデータ作成
	account := &models.SocialAccount{
		ID:          "account-123",
		UserID:      "user-123",
		Provider:    models.ProviderGoogle,
		ProviderID:  "google-123",
		Email:       "old@example.com",
		DisplayName: "Old Name",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	require.NoError(t, repo.Create(context.Background(), account))

	// 更新
	account.Email = "new@example.com"
	account.DisplayName = "New Name"
	account.ProfileData = map[string]interface{}{
		"updated": true,
	}

	err := repo.Update(context.Background(), account)
	require.NoError(t, err)

	// 更新内容を確認
	updated, err := repo.GetByID(context.Background(), account.ID)
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", updated.Email)
	assert.Equal(t, "New Name", updated.DisplayName)
}

func TestSocialAccountRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewSocialAccountRepository(db)

	// テストデータ作成
	account := &models.SocialAccount{
		ID:          "account-123",
		UserID:      "user-123",
		Provider:    models.ProviderGoogle,
		ProviderID:  "google-123",
		Email:       "user@example.com",
		DisplayName: "Test User",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	require.NoError(t, repo.Create(context.Background(), account))

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "delete existing account",
			id:      "account-123",
			wantErr: false,
		},
		{
			name:    "delete non-existent account",
			id:      "account-999",
			wantErr: false, // 削除は冪等操作として扱う
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.Delete(context.Background(), tt.id)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// setupTestDB はテスト用のSQLiteデータベースをセットアップする
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	// テーブル作成
	schema := `
		CREATE TABLE social_accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			email TEXT,
			display_name TEXT,
			profile_data TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			UNIQUE(provider, provider_id)
		);
	`

	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}