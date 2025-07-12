package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dqx0/glen/auth-service/internal/oauth2/models"
)

// OAuth2Repository provides database operations for OAuth2 entities
type OAuth2Repository struct {
	db *sql.DB
}

// NewOAuth2Repository creates a new OAuth2Repository
func NewOAuth2Repository(db *sql.DB) *OAuth2Repository {
	return &OAuth2Repository{
		db: db,
	}
}

// Client operations

// CreateClient creates a new OAuth2 client
func (r *OAuth2Repository) CreateClient(ctx context.Context, client *models.OAuth2Client) error {
	query := `
		INSERT INTO oauth2_clients (
			id, user_id, client_id, client_secret_hash, name, description,
			redirect_uris, scopes, grant_types, response_types,
			token_endpoint_auth_method, is_public, is_active, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := r.db.ExecContext(ctx, query,
		client.ID, client.UserID, client.ClientID, client.ClientSecretHash,
		client.Name, client.Description, client.RedirectURIsJSON, client.ScopesJSON,
		client.GrantTypesJSON, client.ResponseTypesJSON, client.TokenEndpointAuthMethod,
		client.IsPublic, client.IsActive, client.CreatedAt, client.UpdatedAt,
	)
	
	return err
}

// GetClientByClientID retrieves an OAuth2 client by client_id
func (r *OAuth2Repository) GetClientByClientID(ctx context.Context, clientID string) (*models.OAuth2Client, error) {
	query := `
		SELECT id, user_id, client_id, client_secret_hash, name, description,
			   redirect_uris, scopes, grant_types, response_types,
			   token_endpoint_auth_method, is_public, is_active, created_at, updated_at
		FROM oauth2_clients 
		WHERE client_id = ? AND is_active = TRUE
	`
	
	client := &models.OAuth2Client{}
	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ID, &client.UserID, &client.ClientID, &client.ClientSecretHash,
		&client.Name, &client.Description, &client.RedirectURIsJSON, &client.ScopesJSON,
		&client.GrantTypesJSON, &client.ResponseTypesJSON, &client.TokenEndpointAuthMethod,
		&client.IsPublic, &client.IsActive, &client.CreatedAt, &client.UpdatedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Deserialize JSON fields
	if err := client.DeserializeFromDB(); err != nil {
		return nil, fmt.Errorf("failed to deserialize client: %w", err)
	}
	
	return client, nil
}

// GetClientsByUserID retrieves all OAuth2 clients for a user
func (r *OAuth2Repository) GetClientsByUserID(ctx context.Context, userID string) ([]*models.OAuth2Client, error) {
	query := `
		SELECT id, user_id, client_id, client_secret_hash, name, description,
			   redirect_uris, scopes, grant_types, response_types,
			   token_endpoint_auth_method, is_public, is_active, created_at, updated_at
		FROM oauth2_clients 
		WHERE user_id = ? 
		ORDER BY created_at DESC
	`
	
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []*models.OAuth2Client
	for rows.Next() {
		client := &models.OAuth2Client{}
		err := rows.Scan(
			&client.ID, &client.UserID, &client.ClientID, &client.ClientSecretHash,
			&client.Name, &client.Description, &client.RedirectURIsJSON, &client.ScopesJSON,
			&client.GrantTypesJSON, &client.ResponseTypesJSON, &client.TokenEndpointAuthMethod,
			&client.IsPublic, &client.IsActive, &client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		
		// Deserialize JSON fields
		if err := client.DeserializeFromDB(); err != nil {
			return nil, fmt.Errorf("failed to deserialize client: %w", err)
		}
		
		clients = append(clients, client)
	}
	
	return clients, rows.Err()
}

// UpdateClient updates an existing OAuth2 client
func (r *OAuth2Repository) UpdateClient(ctx context.Context, client *models.OAuth2Client) error {
	query := `
		UPDATE oauth2_clients 
		SET name = ?, description = ?, redirect_uris = ?, scopes = ?,
			grant_types = ?, response_types = ?, token_endpoint_auth_method = ?,
			is_public = ?, is_active = ?, updated_at = ?
		WHERE client_id = ? AND user_id = ?
	`
	
	_, err := r.db.ExecContext(ctx, query,
		client.Name, client.Description, client.RedirectURIsJSON, client.ScopesJSON,
		client.GrantTypesJSON, client.ResponseTypesJSON, client.TokenEndpointAuthMethod,
		client.IsPublic, client.IsActive, client.UpdatedAt,
		client.ClientID, client.UserID,
	)
	
	return err
}

// UpdateClient updates an existing OAuth2 client
func (r *OAuth2Repository) UpdateClient(ctx context.Context, client *models.OAuth2Client) error {
	query := `
		UPDATE oauth2_clients 
		SET name = ?, description = ?, redirect_uris = ?, scopes = ?,
			grant_types = ?, response_types = ?, token_endpoint_auth_method = ?,
			is_public = ?, is_active = ?, updated_at = ?
		WHERE client_id = ? AND user_id = ?
	`
	
	_, err := r.db.ExecContext(ctx, query,
		client.Name, client.Description, client.RedirectURIsJSON, client.ScopesJSON,
		client.GrantTypesJSON, client.ResponseTypesJSON, client.TokenEndpointAuthMethod,
		client.IsPublic, client.IsActive, client.UpdatedAt,
		client.ClientID, client.UserID,
	)
	
	return err
}

// DeleteClient deletes an OAuth2 client
func (r *OAuth2Repository) DeleteClient(ctx context.Context, clientID, userID string) error {
	query := `DELETE FROM oauth2_clients WHERE client_id = ? AND user_id = ?`
	_, err := r.db.ExecContext(ctx, query, clientID, userID)
	return err
}

// Authorization Code operations

// CreateAuthorizationCode creates a new authorization code
func (r *OAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	query := `
		INSERT INTO oauth2_authorization_codes (
			id, code_hash, client_id, user_id, redirect_uri, scopes, state,
			code_challenge, code_challenge_method, expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := r.db.ExecContext(ctx, query,
		code.ID, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI,
		code.ScopesJSON, code.State, code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.CreatedAt,
	)
	
	return err
}

// GetAuthorizationCodeByHash retrieves an authorization code by its hash
func (r *OAuth2Repository) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*models.AuthorizationCode, error) {
	query := `
		SELECT id, code_hash, client_id, user_id, redirect_uri, scopes, state,
			   code_challenge, code_challenge_method, expires_at, used_at, created_at
		FROM oauth2_authorization_codes 
		WHERE code_hash = ?
	`
	
	code := &models.AuthorizationCode{}
	err := r.db.QueryRowContext(ctx, query, codeHash).Scan(
		&code.ID, &code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI,
		&code.ScopesJSON, &code.State, &code.CodeChallenge, &code.CodeChallengeMethod,
		&code.ExpiresAt, &code.UsedAt, &code.CreatedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Deserialize JSON fields
	if err := code.DeserializeFromDB(); err != nil {
		return nil, fmt.Errorf("failed to deserialize authorization code: %w", err)
	}
	
	return code, nil
}

// MarkAuthorizationCodeAsUsed marks an authorization code as used
func (r *OAuth2Repository) MarkAuthorizationCodeAsUsed(ctx context.Context, codeHash string) error {
	query := `UPDATE oauth2_authorization_codes SET used_at = ? WHERE code_hash = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), codeHash)
	return err
}

// CleanupExpiredAuthorizationCodes removes expired authorization codes
func (r *OAuth2Repository) CleanupExpiredAuthorizationCodes(ctx context.Context) (int64, error) {
	query := `DELETE FROM oauth2_authorization_codes WHERE expires_at < ?`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Access Token operations

// CreateAccessToken creates a new access token
func (r *OAuth2Repository) CreateAccessToken(ctx context.Context, token *models.OAuth2AccessToken) error {
	query := `
		INSERT INTO oauth2_access_tokens (
			id, token_hash, client_id, user_id, scopes, token_type,
			expires_at, created_at, last_used_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := r.db.ExecContext(ctx, query,
		token.ID, token.TokenHash, token.ClientID, token.UserID,
		token.ScopesJSON, token.TokenType, token.ExpiresAt,
		token.CreatedAt, token.LastUsedAt,
	)
	
	return err
}

// GetAccessTokenByHash retrieves an access token by its hash
func (r *OAuth2Repository) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2AccessToken, error) {
	query := `
		SELECT id, token_hash, client_id, user_id, scopes, token_type,
			   expires_at, revoked_at, created_at, last_used_at
		FROM oauth2_access_tokens 
		WHERE token_hash = ?
	`
	
	token := &models.OAuth2AccessToken{}
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID, &token.TokenHash, &token.ClientID, &token.UserID,
		&token.ScopesJSON, &token.TokenType, &token.ExpiresAt,
		&token.RevokedAt, &token.CreatedAt, &token.LastUsedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Deserialize JSON fields
	if err := token.DeserializeFromDB(); err != nil {
		return nil, fmt.Errorf("failed to deserialize access token: %w", err)
	}
	
	return token, nil
}

// UpdateAccessTokenLastUsed updates the last used timestamp of an access token
func (r *OAuth2Repository) UpdateAccessTokenLastUsed(ctx context.Context, tokenHash string) error {
	query := `UPDATE oauth2_access_tokens SET last_used_at = ? WHERE token_hash = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), tokenHash)
	return err
}

// RevokeAccessToken revokes an access token
func (r *OAuth2Repository) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	query := `UPDATE oauth2_access_tokens SET revoked_at = ? WHERE token_hash = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), tokenHash)
	return err
}

// CleanupExpiredAccessTokens removes expired access tokens
func (r *OAuth2Repository) CleanupExpiredAccessTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM oauth2_access_tokens WHERE expires_at < ?`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Refresh Token operations

// CreateRefreshToken creates a new refresh token
func (r *OAuth2Repository) CreateRefreshToken(ctx context.Context, token *models.OAuth2RefreshToken) error {
	query := `
		INSERT INTO oauth2_refresh_tokens (
			id, token_hash, access_token_id, client_id, user_id, scopes,
			expires_at, created_at, last_used_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := r.db.ExecContext(ctx, query,
		token.ID, token.TokenHash, token.AccessTokenID, token.ClientID,
		token.UserID, token.ScopesJSON, token.ExpiresAt,
		token.CreatedAt, token.LastUsedAt,
	)
	
	return err
}

// GetRefreshTokenByHash retrieves a refresh token by its hash
func (r *OAuth2Repository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2RefreshToken, error) {
	query := `
		SELECT id, token_hash, access_token_id, client_id, user_id, scopes,
			   expires_at, revoked_at, created_at, last_used_at
		FROM oauth2_refresh_tokens 
		WHERE token_hash = ?
	`
	
	token := &models.OAuth2RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID, &token.TokenHash, &token.AccessTokenID, &token.ClientID,
		&token.UserID, &token.ScopesJSON, &token.ExpiresAt,
		&token.RevokedAt, &token.CreatedAt, &token.LastUsedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Deserialize JSON fields
	if err := token.DeserializeFromDB(); err != nil {
		return nil, fmt.Errorf("failed to deserialize refresh token: %w", err)
	}
	
	return token, nil
}

// UpdateRefreshTokenLastUsed updates the last used timestamp of a refresh token
func (r *OAuth2Repository) UpdateRefreshTokenLastUsed(ctx context.Context, tokenHash string) error {
	query := `UPDATE oauth2_refresh_tokens SET last_used_at = ? WHERE token_hash = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), tokenHash)
	return err
}

// RevokeRefreshToken revokes a refresh token
func (r *OAuth2Repository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	query := `UPDATE oauth2_refresh_tokens SET revoked_at = ? WHERE token_hash = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), tokenHash)
	return err
}

// RevokeRefreshTokensByAccessTokenID revokes all refresh tokens associated with an access token
func (r *OAuth2Repository) RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error {
	query := `UPDATE oauth2_refresh_tokens SET revoked_at = ? WHERE access_token_id = ? AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, time.Now(), accessTokenID)
	return err
}

// CleanupExpiredRefreshTokens removes expired refresh tokens
func (r *OAuth2Repository) CleanupExpiredRefreshTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM oauth2_refresh_tokens WHERE expires_at < ?`
	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}