package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dqx0/glen/auth-service/internal/models"
)

var (
	ErrTokenNotFound = errors.New("token not found")
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, token *models.Token) error {
	// スコープをJSON文字列に変換
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO api_tokens (id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var expiresAt interface{}
	if !token.ExpiresAt.IsZero() {
		expiresAt = token.ExpiresAt
	}

	_, err = r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.Type,
		token.TokenHash,
		token.Name,
		string(scopesJSON),
		expiresAt,
		token.LastUsedAt,
		token.CreatedAt,
	)

	return err
}

func (r *TokenRepository) GetByID(ctx context.Context, id string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE id = ?
	`

	token := &models.Token{}
	var scopesJSON string
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&token.ID,
		&token.UserID,
		&token.Type,
		&token.TokenHash,
		&token.Name,
		&scopesJSON,
		&expiresAt,
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	// スコープをJSONから復元
	if err := json.Unmarshal([]byte(scopesJSON), &token.Scopes); err != nil {
		return nil, err
	}

	// 期限の設定
	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}

func (r *TokenRepository) GetByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*models.Token
	for rows.Next() {
		token := &models.Token{}
		var scopesJSON string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Type,
			&token.TokenHash,
			&token.Name,
			&scopesJSON,
			&expiresAt,
			&token.LastUsedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// スコープをJSONから復元
		if err := json.Unmarshal([]byte(scopesJSON), &token.Scopes); err != nil {
			return nil, err
		}

		// 期限の設定
		if expiresAt.Valid {
			token.ExpiresAt = expiresAt.Time
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (r *TokenRepository) GetByTypeAndUserID(ctx context.Context, tokenType, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE token_type = ? AND user_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tokenType, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*models.Token
	for rows.Next() {
		token := &models.Token{}
		var scopesJSON string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Type,
			&token.TokenHash,
			&token.Name,
			&scopesJSON,
			&expiresAt,
			&token.LastUsedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// スコープをJSONから復元
		if err := json.Unmarshal([]byte(scopesJSON), &token.Scopes); err != nil {
			return nil, err
		}

		// 期限の設定
		if expiresAt.Valid {
			token.ExpiresAt = expiresAt.Time
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (r *TokenRepository) Update(ctx context.Context, token *models.Token) error {
	// スコープをJSON文字列に変換
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return err
	}

	var expiresAt interface{}
	if !token.ExpiresAt.IsZero() {
		expiresAt = token.ExpiresAt
	}

	query := `
		UPDATE api_tokens
		SET token_hash = ?, name = ?, scopes = ?, expires_at = ?, last_used_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query,
		token.TokenHash,
		token.Name,
		string(scopesJSON),
		expiresAt,
		token.LastUsedAt,
		token.ID,
	)

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

func (r *TokenRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM api_tokens WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

func (r *TokenRepository) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM api_tokens 
		WHERE expires_at IS NOT NULL AND expires_at < ?
	`

	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

func (r *TokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE token_hash = ?
	`

	token := &models.Token{}
	var scopesJSON string
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.Type,
		&token.TokenHash,
		&token.Name,
		&scopesJSON,
		&expiresAt,
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	// スコープをJSONから復元
	if err := json.Unmarshal([]byte(scopesJSON), &token.Scopes); err != nil {
		return nil, err
	}

	// 期限の設定
	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}