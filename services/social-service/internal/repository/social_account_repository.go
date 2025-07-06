package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dqx0/glen/social-service/internal/models"
)

var (
	ErrSocialAccountNotFound = errors.New("social account not found")
	ErrDuplicateSocialAccount = errors.New("social account already exists")
)

// SocialAccountRepository はソーシャルアカウントの永続化を担当する
type SocialAccountRepository struct {
	db *sql.DB
}

// NewSocialAccountRepository は新しいSocialAccountRepositoryを作成する
func NewSocialAccountRepository(db *sql.DB) *SocialAccountRepository {
	return &SocialAccountRepository{db: db}
}

// Create はソーシャルアカウントを作成する
func (r *SocialAccountRepository) Create(ctx context.Context, account *models.SocialAccount) error {
	profileDataJSON, err := json.Marshal(account.ProfileData)
	if err != nil {
		return fmt.Errorf("failed to marshal profile data: %w", err)
	}

	query := `
		INSERT INTO social_accounts (
			id, user_id, provider, provider_id, email, display_name, 
			profile_data, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = r.db.ExecContext(ctx, query,
		account.ID,
		account.UserID,
		account.Provider,
		account.ProviderID,
		account.Email,
		account.DisplayName,
		string(profileDataJSON),
		account.CreatedAt,
		account.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateSocialAccount
		}
		return fmt.Errorf("failed to create social account: %w", err)
	}

	return nil
}

// GetByID はIDでソーシャルアカウントを取得する
func (r *SocialAccountRepository) GetByID(ctx context.Context, id string) (*models.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, display_name,
			   profile_data, created_at, updated_at
		FROM social_accounts
		WHERE id = ?
	`

	var account models.SocialAccount
	var profileDataJSON string

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.ProviderID,
		&account.Email,
		&account.DisplayName,
		&profileDataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSocialAccountNotFound
		}
		return nil, fmt.Errorf("failed to get social account: %w", err)
	}

	// JSON デシリアライズ
	if profileDataJSON != "" {
		if err := json.Unmarshal([]byte(profileDataJSON), &account.ProfileData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal profile data: %w", err)
		}
	}

	return &account, nil
}

// GetByUserID はユーザーIDでソーシャルアカウント一覧を取得する
func (r *SocialAccountRepository) GetByUserID(ctx context.Context, userID string) ([]*models.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, display_name,
			   profile_data, created_at, updated_at
		FROM social_accounts
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query social accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*models.SocialAccount

	for rows.Next() {
		var account models.SocialAccount
		var profileDataJSON string

		err := rows.Scan(
			&account.ID,
			&account.UserID,
			&account.Provider,
			&account.ProviderID,
			&account.Email,
			&account.DisplayName,
			&profileDataJSON,
			&account.CreatedAt,
			&account.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan social account: %w", err)
		}

		// JSON デシリアライズ
		if profileDataJSON != "" {
			if err := json.Unmarshal([]byte(profileDataJSON), &account.ProfileData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal profile data: %w", err)
			}
		}

		accounts = append(accounts, &account)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate social accounts: %w", err)
	}

	return accounts, nil
}

// GetByProviderAndProviderID はプロバイダーとプロバイダーIDでソーシャルアカウントを取得する
func (r *SocialAccountRepository) GetByProviderAndProviderID(ctx context.Context, provider, providerID string) (*models.SocialAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, display_name,
			   profile_data, created_at, updated_at
		FROM social_accounts
		WHERE provider = ? AND provider_id = ?
	`

	var account models.SocialAccount
	var profileDataJSON string

	err := r.db.QueryRowContext(ctx, query, provider, providerID).Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.ProviderID,
		&account.Email,
		&account.DisplayName,
		&profileDataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSocialAccountNotFound
		}
		return nil, fmt.Errorf("failed to get social account: %w", err)
	}

	// JSON デシリアライズ
	if profileDataJSON != "" {
		if err := json.Unmarshal([]byte(profileDataJSON), &account.ProfileData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal profile data: %w", err)
		}
	}

	return &account, nil
}

// Update はソーシャルアカウントを更新する
func (r *SocialAccountRepository) Update(ctx context.Context, account *models.SocialAccount) error {
	profileDataJSON, err := json.Marshal(account.ProfileData)
	if err != nil {
		return fmt.Errorf("failed to marshal profile data: %w", err)
	}

	query := `
		UPDATE social_accounts SET
			email = ?, display_name = ?, profile_data = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query,
		account.Email,
		account.DisplayName,
		string(profileDataJSON),
		account.UpdatedAt,
		account.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update social account: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSocialAccountNotFound
	}

	return nil
}

// Delete はソーシャルアカウントを削除する
func (r *SocialAccountRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM social_accounts WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete social account: %w", err)
	}

	// 削除は冪等操作として扱う（既に存在しない場合もエラーにしない）
	return nil
}

// DeleteByUserID はユーザーIDでソーシャルアカウントを全て削除する
func (r *SocialAccountRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM social_accounts WHERE user_id = ?`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete social accounts: %w", err)
	}

	return nil
}

// isUniqueViolation はユニーク制約違反かどうかを判定する
func isUniqueViolation(err error) bool {
	// SQLiteの場合のユニーク制約違反を検出
	// 実際のPostgreSQLでは別の方法を使用する
	return err != nil && 
		   (contains(err.Error(), "UNIQUE constraint failed") ||
			contains(err.Error(), "duplicate key"))
}

// contains は文字列が含まれるかチェックする
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || len(substr) == 0 || 
			indexOf(s, substr) >= 0)
}

// indexOf は部分文字列のインデックスを返す
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// IsErrSocialAccountNotFound はソーシャルアカウントが見つからないエラーかどうかを判定する
func IsErrSocialAccountNotFound(err error) bool {
	return errors.Is(err, ErrSocialAccountNotFound)
}