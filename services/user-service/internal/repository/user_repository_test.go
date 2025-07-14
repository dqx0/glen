package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/user-service/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestUserRepository_Create(t *testing.T) {
	// モックDBを使用した統合テスト
	t.Run("create user successfully", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		user, err := models.NewUser("testuser", "test@example.com", "password123")
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), user)
		require.NoError(t, err)
		
		// 作成されたユーザーを取得して検証
		retrievedUser, err := repo.GetByUsername(context.Background(), "testuser")
		require.NoError(t, err)
		require.NotNil(t, retrievedUser)
		
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
		assert.Equal(t, user.Email, retrievedUser.Email)
		assert.Equal(t, user.IsActive(), retrievedUser.IsActive())
	})
	
	t.Run("create user with duplicate username fails", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		
		// 最初のユーザーを作成
		user1, err := models.NewUser("testuser", "test1@example.com", "password123")
		require.NoError(t, err)
		err = repo.Create(context.Background(), user1)
		require.NoError(t, err)
		
		// 同じユーザー名で再度作成を試みる
		user2, err := models.NewUser("testuser", "test2@example.com", "password123")
		require.NoError(t, err)
		err = repo.Create(context.Background(), user2)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UNIQUE constraint failed: users.username")
	})
}

func TestUserRepository_GetByUsername(t *testing.T) {
	t.Run("get existing user", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		user, err := models.NewUser("testuser", "test@example.com", "password123")
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), user)
		require.NoError(t, err)
		
		retrievedUser, err := repo.GetByUsername(context.Background(), "testuser")
		require.NoError(t, err)
		require.NotNil(t, retrievedUser)
		
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Username, retrievedUser.Username)
	})
	
	t.Run("get non-existent user", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		
		user, err := repo.GetByUsername(context.Background(), "nonexistent")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrUserNotFound, err)
	})
}

func TestUserRepository_GetByEmail(t *testing.T) {
	t.Run("get existing user by email", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		user, err := models.NewUser("testuser", "test@example.com", "password123")
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), user)
		require.NoError(t, err)
		
		retrievedUser, err := repo.GetByEmail(context.Background(), "test@example.com")
		require.NoError(t, err)
		require.NotNil(t, retrievedUser)
		
		assert.Equal(t, user.ID, retrievedUser.ID)
		assert.Equal(t, user.Email, retrievedUser.Email)
	})
	
	t.Run("get non-existent user by email", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		
		user, err := repo.GetByEmail(context.Background(), "nonexistent@example.com")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, ErrUserNotFound, err)
	})
}

func TestUserRepository_Update(t *testing.T) {
	t.Run("update user successfully", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()
		
		repo := NewUserRepository(db)
		user, err := models.NewUser("testuser", "test@example.com", "password123")
		require.NoError(t, err)
		
		err = repo.Create(context.Background(), user)
		require.NoError(t, err)
		
		// ユーザー情報を更新
		user.Email = "updated@example.com"
		user.SetEmailVerified(true)
		
		err = repo.Update(context.Background(), user)
		require.NoError(t, err)
		
		// 更新されたユーザーを取得
		retrievedUser, err := repo.GetByUsername(context.Background(), "testuser")
		require.NoError(t, err)
		
		assert.Equal(t, "updated@example.com", retrievedUser.Email)
		assert.True(t, retrievedUser.EmailVerified)
	})
}

// setupTestDB はテスト用のインメモリSQLiteデータベースを作成
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	
	// テーブル作成
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE,
			password_hash TEXT,
			email_verified BOOLEAN DEFAULT FALSE,
			status VARCHAR(20) DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			organization_id TEXT,
			parent_user_id TEXT
		)
	`)
	require.NoError(t, err)
	
	return db
}