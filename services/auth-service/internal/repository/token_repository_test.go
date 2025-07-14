package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/auth-service/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestTokenRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	t.Run("create refresh token successfully", func(t *testing.T) {
		token, err := models.NewRefreshToken("user-123", "test-session", []string{"user:read", "user:write"})
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), token)
		require.NoError(t, err)
		
		// 作成されたトークンを取得して検証
		retrievedToken, err := repo.GetByID(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedToken)
		
		assert.Equal(t, token.ID, retrievedToken.ID)
		assert.Equal(t, token.UserID, retrievedToken.UserID)
		assert.Equal(t, token.Type, retrievedToken.Type)
		assert.Equal(t, token.TokenHash, retrievedToken.TokenHash)
		assert.Equal(t, token.Name, retrievedToken.Name)
		assert.Equal(t, token.Scopes, retrievedToken.Scopes)
	})
	
	t.Run("create API key successfully", func(t *testing.T) {
		token, err := models.NewAPIKey("user-456", "production-api", []string{"api:read", "api:write"})
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), token)
		require.NoError(t, err)
		
		// 作成されたトークンを取得して検証
		retrievedToken, err := repo.GetByID(context.Background(), token.ID)
		require.NoError(t, err)
		require.NotNil(t, retrievedToken)
		
		assert.Equal(t, token.Type, models.TokenTypeAPIKey)
		assert.True(t, retrievedToken.ExpiresAt.IsZero()) // API Keyは期限なし
	})
}

func TestTokenRepository_GetByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	// テストデータ作成
	userID := "user-123"
	token1, err := models.NewRefreshToken(userID, "session-1", []string{"user:read"})
	require.NoError(t, err)
	token2, err := models.NewAPIKey(userID, "api-key-1", []string{"api:read"})
	require.NoError(t, err)
	
	err = repo.Create(context.Background(), token1)
	require.NoError(t, err)
	err = repo.Create(context.Background(), token2)
	require.NoError(t, err)
	
	t.Run("get tokens by user ID", func(t *testing.T) {
		tokens, err := repo.GetByUserID(context.Background(), userID)
		require.NoError(t, err)
		
		assert.Len(t, tokens, 2)
		
		// トークンタイプで検証
		tokenTypes := make(map[string]bool)
		for _, token := range tokens {
			assert.Equal(t, userID, token.UserID)
			tokenTypes[token.Type] = true
		}
		
		assert.True(t, tokenTypes[models.TokenTypeRefresh])
		assert.True(t, tokenTypes[models.TokenTypeAPIKey])
	})
	
	t.Run("get tokens by non-existent user", func(t *testing.T) {
		tokens, err := repo.GetByUserID(context.Background(), "non-existent")
		require.NoError(t, err)
		assert.Empty(t, tokens)
	})
}

func TestTokenRepository_GetByTypeAndUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	userID := "user-123"
	
	// 複数のRefresh Tokenを作成
	token1, err := models.NewRefreshToken(userID, "session-1", []string{"user:read"})
	require.NoError(t, err)
	token2, err := models.NewRefreshToken(userID, "session-2", []string{"user:write"})
	require.NoError(t, err)
	apiKey, err := models.NewAPIKey(userID, "api-key", []string{"api:read"})
	require.NoError(t, err)
	
	err = repo.Create(context.Background(), token1)
	require.NoError(t, err)
	err = repo.Create(context.Background(), token2)
	require.NoError(t, err)
	err = repo.Create(context.Background(), apiKey)
	require.NoError(t, err)
	
	t.Run("get refresh tokens only", func(t *testing.T) {
		tokens, err := repo.GetByTypeAndUserID(context.Background(), models.TokenTypeRefresh, userID)
		require.NoError(t, err)
		
		assert.Len(t, tokens, 2)
		for _, token := range tokens {
			assert.Equal(t, models.TokenTypeRefresh, token.Type)
			assert.Equal(t, userID, token.UserID)
		}
	})
	
	t.Run("get API keys only", func(t *testing.T) {
		tokens, err := repo.GetByTypeAndUserID(context.Background(), models.TokenTypeAPIKey, userID)
		require.NoError(t, err)
		
		assert.Len(t, tokens, 1)
		assert.Equal(t, models.TokenTypeAPIKey, tokens[0].Type)
	})
}

func TestTokenRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	token, err := models.NewRefreshToken("user-123", "test-session", []string{"user:read"})
	require.NoError(t, err)
	
	err = repo.Create(context.Background(), token)
	require.NoError(t, err)
	
	t.Run("update last used time", func(t *testing.T) {
		originalTime := token.LastUsedAt
		
		time.Sleep(10 * time.Millisecond)
		token.UpdateLastUsed()
		
		err = repo.Update(context.Background(), token)
		require.NoError(t, err)
		
		// 更新されたトークンを取得
		updatedToken, err := repo.GetByID(context.Background(), token.ID)
		require.NoError(t, err)
		
		assert.True(t, updatedToken.LastUsedAt.After(originalTime))
	})
}

func TestTokenRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	token, err := models.NewRefreshToken("user-123", "test-session", []string{"user:read"})
	require.NoError(t, err)
	
	err = repo.Create(context.Background(), token)
	require.NoError(t, err)
	
	t.Run("delete token successfully", func(t *testing.T) {
		err = repo.Delete(context.Background(), token.ID)
		require.NoError(t, err)
		
		// 削除されたことを確認
		_, err = repo.GetByID(context.Background(), token.ID)
		assert.Error(t, err)
		assert.Equal(t, ErrTokenNotFound, err)
	})
	
	t.Run("delete non-existent token", func(t *testing.T) {
		err = repo.Delete(context.Background(), "non-existent")
		assert.Error(t, err)
		assert.Equal(t, ErrTokenNotFound, err)
	})
}

func TestTokenRepository_DeleteExpiredTokens(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	repo := NewTokenRepository(db)
	
	// 期限切れのトークンを作成（手動で期限を過去に設定）
	expiredToken, err := models.NewRefreshToken("user-123", "expired-session", []string{"user:read"})
	require.NoError(t, err)
	expiredToken.ExpiresAt = time.Now().Add(-time.Hour) // 1時間前に期限切れ
	
	// 有効なトークンを作成
	validToken, err := models.NewRefreshToken("user-456", "valid-session", []string{"user:read"})
	require.NoError(t, err)
	
	// API Key（期限なし）
	apiKey, err := models.NewAPIKey("user-789", "api-key", []string{"api:read"})
	require.NoError(t, err)
	
	err = repo.Create(context.Background(), expiredToken)
	require.NoError(t, err)
	err = repo.Create(context.Background(), validToken)
	require.NoError(t, err)
	err = repo.Create(context.Background(), apiKey)
	require.NoError(t, err)
	
	t.Run("delete expired tokens", func(t *testing.T) {
		deletedCount, err := repo.DeleteExpiredTokens(context.Background())
		require.NoError(t, err)
		
		assert.Equal(t, int64(1), deletedCount) // 期限切れトークンが1つ削除される
		
		// 期限切れトークンが削除されていることを確認
		_, err = repo.GetByID(context.Background(), expiredToken.ID)
		assert.Error(t, err)
		
		// 有効なトークンは残っていることを確認
		_, err = repo.GetByID(context.Background(), validToken.ID)
		assert.NoError(t, err)
		
		// API Keyは残っていることを確認
		_, err = repo.GetByID(context.Background(), apiKey.ID)
		assert.NoError(t, err)
	})
}

// setupTestDB はテスト用のインメモリSQLiteデータベースを作成
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	
	// api_tokensテーブル作成
	_, err = db.Exec(`
		CREATE TABLE api_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token_type TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			scopes TEXT,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)
	`)
	require.NoError(t, err)
	
	return db
}