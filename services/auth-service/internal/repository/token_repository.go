package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/dqx0/glen/auth-service/internal/models"
	"github.com/lib/pq"
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
	var query string
	var args []interface{}

	if token.Type == models.TokenTypeRefresh {
		// refresh_tokens テーブルに挿入
		query = `
			INSERT INTO refresh_tokens (id, user_id, token_hash, name, scopes, expires_at, created_at, last_used_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`
		args = []interface{}{
			token.ID,
			token.UserID,
			token.TokenHash,
			token.Name,
			pq.Array(token.Scopes), // PostgreSQLのtext[]型として挿入
			token.ExpiresAt,
			token.CreatedAt,
			token.LastUsedAt,
		}
	} else if token.Type == models.TokenTypeAPIKey {
		// api_keys テーブルに挿入 (expires_atは不要)
		query = `
			INSERT INTO api_keys (id, user_id, key_hash, name, scopes, created_at, last_used_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
		args = []interface{}{
			token.ID,
			token.UserID,
			token.TokenHash,
			token.Name,
			pq.Array(token.Scopes), // PostgreSQLのtext[]型として挿入
			token.CreatedAt,
			token.LastUsedAt,
		}
	} else {
		return errors.New("unsupported token type")
	}

	_, err := r.db.ExecContext(ctx, query, args...)

	return err
}

func (r *TokenRepository) GetByID(ctx context.Context, id string) (*models.Token, error) {
	// まずrefresh_tokensから検索
	if token, err := r.getRefreshTokenByID(ctx, id); err == nil {
		return token, nil
	}

	// 次にapi_keysから検索
	if token, err := r.getAPIKeyByID(ctx, id); err == nil {
		return token, nil
	}

	return nil, ErrTokenNotFound
}

func (r *TokenRepository) getRefreshTokenByID(ctx context.Context, id string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM refresh_tokens
		WHERE id = $1
	`

	token := &models.Token{Type: models.TokenTypeRefresh}
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
		&expiresAt,
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}

func (r *TokenRepository) getAPIKeyByID(ctx context.Context, id string) (*models.Token, error) {
	query := `
		SELECT id, user_id, key_hash, name, scopes, last_used_at, created_at
		FROM api_keys
		WHERE id = $1
	`

	token := &models.Token{Type: models.TokenTypeAPIKey}

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	return token, err
}

func (r *TokenRepository) GetByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	var tokens []*models.Token

	// refresh_tokensから取得
	refreshTokens, err := r.getRefreshTokensByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	tokens = append(tokens, refreshTokens...)

	// api_keysから取得
	apiKeys, err := r.getAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	tokens = append(tokens, apiKeys...)

	return tokens, nil
}

func (r *TokenRepository) GetByTypeAndUserID(ctx context.Context, tokenType, userID string) ([]*models.Token, error) {
	if tokenType == models.TokenTypeRefresh {
		return r.getRefreshTokensByUserID(ctx, userID)
	} else if tokenType == models.TokenTypeAPIKey {
		return r.getAPIKeysByUserID(ctx, userID)
	}

	return nil, errors.New("unsupported token type")
}

func (r *TokenRepository) Update(ctx context.Context, token *models.Token) error {
	var query string
	var args []interface{}

	if token.Type == models.TokenTypeRefresh {
		query = `
			UPDATE refresh_tokens
			SET token_hash = $1, name = $2, scopes = $3, expires_at = $4, last_used_at = $5
			WHERE id = $6
		`
		args = []interface{}{
			token.TokenHash,
			token.Name,
			pq.Array(token.Scopes),
			token.ExpiresAt,
			token.LastUsedAt,
			token.ID,
		}
	} else if token.Type == models.TokenTypeAPIKey {
		query = `
			UPDATE api_keys
			SET key_hash = $1, name = $2, scopes = $3, last_used_at = $4
			WHERE id = $5
		`
		args = []interface{}{
			token.TokenHash,
			token.Name,
			pq.Array(token.Scopes),
			token.LastUsedAt,
			token.ID,
		}
	} else {
		return errors.New("unsupported token type")
	}

	result, err := r.db.ExecContext(ctx, query, args...)
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
	// refresh_tokensから削除を試行
	query := `DELETE FROM refresh_tokens WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected > 0 {
		return nil
	}

	// api_keysから削除を試行
	query = `DELETE FROM api_keys WHERE id = $1`
	result, err = r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

func (r *TokenRepository) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	// refresh_tokensから期限切れトークンを削除
	query := `DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

func (r *TokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.Token, error) {
	// まずrefresh_tokensから検索
	if token, err := r.getRefreshTokenByHash(ctx, tokenHash); err == nil {
		return token, nil
	}

	// 次にapi_keysから検索
	if token, err := r.getAPIKeyByHash(ctx, tokenHash); err == nil {
		return token, nil
	}

	return nil, ErrTokenNotFound
}

func (r *TokenRepository) getRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	token := &models.Token{Type: models.TokenTypeRefresh}
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
		&expiresAt,
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}

func (r *TokenRepository) getAPIKeyByHash(ctx context.Context, tokenHash string) (*models.Token, error) {
	query := `
		SELECT id, user_id, key_hash, name, scopes, last_used_at, created_at
		FROM api_keys
		WHERE key_hash = $1
	`

	token := &models.Token{Type: models.TokenTypeAPIKey}

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
		&token.LastUsedAt,
		&token.CreatedAt,
	)

	return token, err
}

func (r *TokenRepository) getRefreshTokensByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM refresh_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*models.Token
	for rows.Next() {
		token := &models.Token{Type: models.TokenTypeRefresh}
		var expiresAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&token.Name,
			pq.Array(&token.Scopes),
			&expiresAt,
			&token.LastUsedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if expiresAt.Valid {
			token.ExpiresAt = expiresAt.Time
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (r *TokenRepository) getAPIKeysByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, key_hash, name, scopes, last_used_at, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*models.Token
	for rows.Next() {
		token := &models.Token{Type: models.TokenTypeAPIKey}

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.TokenHash,
			&token.Name,
			pq.Array(&token.Scopes),
			&token.LastUsedAt,
			&token.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}