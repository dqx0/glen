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
	query := `
		INSERT INTO api_tokens (id, user_id, token_type, token_hash, name, scopes, expires_at, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	var expiresAt interface{}
	if token.ExpiresAt.IsZero() {
		expiresAt = nil
	} else {
		expiresAt = token.ExpiresAt
	}

	_, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.Type,
		token.TokenHash,
		token.Name,
		pq.Array(token.Scopes),
		expiresAt,
		token.CreatedAt,
		token.LastUsedAt,
	)

	return err
}

func (r *TokenRepository) GetByID(ctx context.Context, id string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE id = $1
	`

	token := &models.Token{}
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&token.ID,
		&token.UserID,
		&token.Type,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
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

	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}


func (r *TokenRepository) GetByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
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
		token := &models.Token{}
		var expiresAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Type,
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

func (r *TokenRepository) GetByTypeAndUserID(ctx context.Context, tokenType, userID string) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_hash, name, scopes, expires_at, last_used_at, created_at
		FROM api_tokens
		WHERE token_type = $1 AND user_id = $2
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
		var expiresAt sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.Type,
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

func (r *TokenRepository) Update(ctx context.Context, token *models.Token) error {
	query := `
		UPDATE api_tokens
		SET token_hash = $1, name = $2, scopes = $3, expires_at = $4, last_used_at = $5
		WHERE id = $6
	`

	var expiresAt interface{}
	if token.ExpiresAt.IsZero() {
		expiresAt = nil
	} else {
		expiresAt = token.ExpiresAt
	}

	result, err := r.db.ExecContext(ctx, query,
		token.TokenHash,
		token.Name,
		pq.Array(token.Scopes),
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
	query := `DELETE FROM api_tokens WHERE id = $1`
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
	query := `DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`
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
		WHERE token_hash = $1
	`

	token := &models.Token{}
	var expiresAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.Type,
		&token.TokenHash,
		&token.Name,
		pq.Array(&token.Scopes),
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

	if expiresAt.Valid {
		token.ExpiresAt = expiresAt.Time
	}

	return token, nil
}

