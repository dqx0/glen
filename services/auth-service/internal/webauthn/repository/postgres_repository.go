package repository

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// postgresWebAuthnRepository implements WebAuthnRepository for PostgreSQL
type postgresWebAuthnRepository struct {
	db      *sqlx.DB
	config  *RepositoryConfig
	timeout time.Duration
}

// NewPostgreSQLWebAuthnRepository creates a new PostgreSQL WebAuthn repository
func NewPostgreSQLWebAuthnRepository(db *sqlx.DB, config *RepositoryConfig) WebAuthnRepository {
	if config == nil {
		config = &RepositoryConfig{
			QueryTimeout: 30 * time.Second,
		}
	}
	
	return &postgresWebAuthnRepository{
		db:      db,
		config:  config,
		timeout: config.QueryTimeout,
	}
}

// CreateCredential creates a new WebAuthn credential
func (r *postgresWebAuthnRepository) CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate credential before insertion
	if err := credential.Validate(); err != nil {
		return NewRepositoryError(ErrRepositoryConstraint, "Invalid credential data", err)
	}

	query := `
		INSERT INTO webauthn_credentials (
			id, user_id, credential_id, public_key, attestation_type,
			transport, user_present, user_verified, backup_eligible, backup_state,
			sign_count, clone_warning, name, last_used_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)`

	// Convert transport slice for database storage
	var transportValue interface{}
	if r.db.DriverName() == "postgres" {
		// PostgreSQL: use array format
		transportStrs := make([]string, len(credential.Transport))
		for i, transport := range credential.Transport {
			transportStrs[i] = string(transport)
		}
		transportValue = pq.Array(transportStrs)
	} else {
		// SQLite: use comma-separated string
		transportValue = models.TransportsToString(credential.Transport)
	}

	_, err := r.db.ExecContext(ctx, query,
		credential.ID,
		credential.UserID,
		credential.CredentialID,
		credential.PublicKey,
		credential.AttestationType,
		transportValue,
		credential.Flags.UserPresent,
		credential.Flags.UserVerified,
		credential.Flags.BackupEligible,
		credential.Flags.BackupState,
		credential.SignCount,
		credential.CloneWarning,
		credential.Name,
		credential.LastUsedAt,
		credential.CreatedAt,
		credential.UpdatedAt,
	)

	if err != nil {
		// Handle PostgreSQL errors
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				return NewRepositoryError(ErrRepositoryConflict, "Credential ID already exists", err)
			case "23503": // foreign_key_violation
				return NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID", err)
			case "23514": // check_violation
				return NewRepositoryError(ErrRepositoryConstraint, "Constraint violation", err)
			}
		}
		
		// Handle SQLite errors (for testing)
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return NewRepositoryError(ErrRepositoryConflict, "Credential ID already exists", err)
		}
		
		return NewRepositoryError(ErrRepositoryInternal, "Failed to create credential", err)
	}

	return nil
}

// GetCredentialsByUserID retrieves all credentials for a user
func (r *postgresWebAuthnRepository) GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate UUID format
	if err := validateUUID(userID); err != nil {
		return nil, NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", err)
	}

	// Use database-agnostic placeholder
	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		WHERE user_id = ?
		ORDER BY created_at DESC`
	if r.db.DriverName() == "postgres" {
		query = `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		WHERE user_id = $1
		ORDER BY created_at DESC`
	}

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to query credentials", err)
	}
	defer rows.Close()

	var credentials []*models.WebAuthnCredential
	for rows.Next() {
		credential := &models.WebAuthnCredential{}
		var transportValue interface{}
		var transportStrs []string
		var transportStr string
		
		// Prepare transport scanning based on database type
		if r.db.DriverName() == "postgres" {
			transportValue = pq.Array(&transportStrs)
		} else {
			transportValue = &transportStr
		}
		
		err := rows.Scan(
			&credential.ID,
			&credential.UserID,
			&credential.CredentialID,
			&credential.PublicKey,
			&credential.AttestationType,
			transportValue,
			&credential.Flags.UserPresent,
			&credential.Flags.UserVerified,
			&credential.Flags.BackupEligible,
			&credential.Flags.BackupState,
			&credential.SignCount,
			&credential.CloneWarning,
			&credential.Name,
			&credential.LastUsedAt,
			&credential.CreatedAt,
			&credential.UpdatedAt,
		)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan credential", err)
		}

		// Convert transport data back to slice of AuthenticatorTransport
		if r.db.DriverName() == "postgres" {
			// PostgreSQL: convert from array
			credential.Transport = make([]models.AuthenticatorTransport, len(transportStrs))
			for i, ts := range transportStrs {
				credential.Transport[i] = models.AuthenticatorTransport(ts)
			}
		} else {
			// SQLite: convert from comma-separated string
			credential.Transport = models.StringToTransports(transportStr)
		}
		
		credentials = append(credentials, credential)
	}

	if err = rows.Err(); err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Row iteration error", err)
	}

	return credentials, nil
}

// GetAllCredentials retrieves all WebAuthn credentials (for passwordless authentication)
func (r *postgresWebAuthnRepository) GetAllCredentials(ctx context.Context) ([]*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to query all credentials", err)
	}
	defer rows.Close()

	var credentials []*models.WebAuthnCredential
	for rows.Next() {
		credential := &models.WebAuthnCredential{}
		var transportArray pq.StringArray

		err := rows.Scan(
			&credential.ID,
			&credential.UserID,
			&credential.CredentialID,
			&credential.PublicKey,
			&credential.AttestationType,
			&transportArray,
			&credential.Flags.UserPresent,
			&credential.Flags.UserVerified,
			&credential.Flags.BackupEligible,
			&credential.Flags.BackupState,
			&credential.SignCount,
			&credential.CloneWarning,
			&credential.Name,
			&credential.LastUsedAt,
			&credential.CreatedAt,
			&credential.UpdatedAt,
		)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan credential", err)
		}

		// Convert transport array
		credential.Transport = make([]models.AuthenticatorTransport, len(transportArray))
		for i, transport := range transportArray {
			credential.Transport[i] = models.AuthenticatorTransport(transport)
		}

		credentials = append(credentials, credential)
	}

	if err := rows.Err(); err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Row iteration error", err)
	}

	return credentials, nil
}

// GetCredentialByID retrieves a credential by its ID
func (r *postgresWebAuthnRepository) GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		WHERE credential_id = $1`

	credential := &models.WebAuthnCredential{}
	var transportValue interface{}
	var transportStrs []string
	var transportStr string

	// Prepare transport scanning based on database type
	if r.db.DriverName() == "postgres" {
		transportValue = pq.Array(&transportStrs)
	} else {
		transportValue = &transportStr
	}

	err := r.db.QueryRowContext(ctx, query, credentialID).Scan(
		&credential.ID,
		&credential.UserID,
		&credential.CredentialID,
		&credential.PublicKey,
		&credential.AttestationType,
		transportValue,
		&credential.Flags.UserPresent,
		&credential.Flags.UserVerified,
		&credential.Flags.BackupEligible,
		&credential.Flags.BackupState,
		&credential.SignCount,
		&credential.CloneWarning,
		&credential.Name,
		&credential.LastUsedAt,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)

	if err != nil {
		// Debug logging
		fmt.Printf("GetCredentialByID error for credential %x: %v\n", credentialID, err)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewRepositoryError(ErrRepositoryNotFound, "Credential not found", err)
		}
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get credential", err)
	}

	// Convert transport data back to slice of AuthenticatorTransport
	if r.db.DriverName() == "postgres" {
		// PostgreSQL: convert from array
		credential.Transport = make([]models.AuthenticatorTransport, len(transportStrs))
		for i, ts := range transportStrs {
			credential.Transport[i] = models.AuthenticatorTransport(ts)
		}
	} else {
		// SQLite: convert from comma-separated string
		credential.Transport = models.StringToTransports(transportStr)
	}
	
	// Flags are now read directly from individual columns

	return credential, nil
}

// GetCredentialByTableID retrieves a credential by its table ID (UUID)
func (r *postgresWebAuthnRepository) GetCredentialByTableID(ctx context.Context, id string) (*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		WHERE id = $1`

	credential := &models.WebAuthnCredential{}
	var transportValue interface{}
	var transportStrs []string
	var transportStr string

	// Prepare transport scanning based on database type
	if r.db.DriverName() == "postgres" {
		transportValue = pq.Array(&transportStrs)
	} else {
		transportValue = &transportStr
	}

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&credential.ID,
		&credential.UserID,
		&credential.CredentialID,
		&credential.PublicKey,
		&credential.AttestationType,
		transportValue,
		&credential.Flags.UserPresent,
		&credential.Flags.UserVerified,
		&credential.Flags.BackupEligible,
		&credential.Flags.BackupState,
		&credential.SignCount,
		&credential.CloneWarning,
		&credential.Name,
		&credential.LastUsedAt,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NewRepositoryError(ErrRepositoryNotFound, "Credential not found", err)
		}
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get credential", err)
	}

	// Convert transport data back to slice of AuthenticatorTransport
	if r.db.DriverName() == "postgres" {
		// PostgreSQL: convert from array
		credential.Transport = make([]models.AuthenticatorTransport, len(transportStrs))
		for i, ts := range transportStrs {
			credential.Transport[i] = models.AuthenticatorTransport(ts)
		}
	} else {
		// SQLite: convert from comma-separated string
		credential.Transport = models.StringToTransports(transportStr)
	}
	
	// Flags are now read directly from individual columns

	return credential, nil
}

// UpdateCredential updates an existing credential
func (r *postgresWebAuthnRepository) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Validate credential before update
	if err := credential.Validate(); err != nil {
		return NewRepositoryError(ErrRepositoryConstraint, "Invalid credential data", err)
	}

	query := `
		UPDATE webauthn_credentials 
		SET public_key = $1, attestation_type = $2, transport = $3, 
			user_present = $4, user_verified = $5, backup_eligible = $6, backup_state = $7,
			sign_count = $8, clone_warning = $9, name = $10, last_used_at = $11, updated_at = $12
		WHERE credential_id = $13`

	// Convert transport slice for database storage
	var transportValue interface{}
	if r.db.DriverName() == "postgres" {
		// PostgreSQL: use array format
		transportStrs := make([]string, len(credential.Transport))
		for i, transport := range credential.Transport {
			transportStrs[i] = string(transport)
		}
		transportValue = pq.Array(transportStrs)
	} else {
		// SQLite: use comma-separated string
		transportValue = models.TransportsToString(credential.Transport)
	}
	credential.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(ctx, query,
		credential.PublicKey,
		credential.AttestationType,
		transportValue,
		credential.Flags.UserPresent,
		credential.Flags.UserVerified,
		credential.Flags.BackupEligible,
		credential.Flags.BackupState,
		credential.SignCount,
		credential.CloneWarning,
		credential.Name,
		credential.LastUsedAt,
		credential.UpdatedAt,
		credential.CredentialID,
	)

	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to update credential", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to get rows affected", err)
	}

	if rowsAffected == 0 {
		return NewRepositoryError(ErrRepositoryNotFound, "Credential not found", nil)
	}

	return nil
}

// DeleteCredential deletes a credential
func (r *postgresWebAuthnRepository) DeleteCredential(ctx context.Context, credentialID []byte) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `DELETE FROM webauthn_credentials WHERE credential_id = $1`

	result, err := r.db.ExecContext(ctx, query, credentialID)
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to delete credential", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to get rows affected", err)
	}

	if rowsAffected == 0 {
		return NewRepositoryError(ErrRepositoryNotFound, "Credential not found", nil)
	}

	return nil
}

// GetCredentialsByUserIDWithTransports retrieves credentials by user ID and transport methods
func (r *postgresWebAuthnRepository) GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if err := validateUUID(userID); err != nil {
		return nil, NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", err)
	}

	if len(transports) == 0 {
		return r.GetCredentialsByUserID(ctx, userID)
	}

	// Build filtering query based on database type
	var query string
	var args []interface{}
	
	if r.db.DriverName() == "postgres" {
		// PostgreSQL: use array overlap operator
		transportStrs := make([]string, len(transports))
		for i, transport := range transports {
			transportStrs[i] = string(transport)
		}
		query = `
			SELECT id, user_id, credential_id, public_key, attestation_type,
				   transport, user_present, user_verified, backup_eligible, backup_state,
				   sign_count, clone_warning, name, last_used_at, created_at, updated_at
			FROM webauthn_credentials 
			WHERE user_id = $1 AND transport && $2
			ORDER BY created_at DESC`
		args = []interface{}{userID, pq.Array(transportStrs)}
	} else {
		// SQLite: use LIKE for comma-separated string matching
		// For simplicity, we'll get all credentials and filter in application code
		query = `
			SELECT id, user_id, credential_id, public_key, attestation_type,
				   transport, user_present, user_verified, backup_eligible, backup_state,
				   sign_count, clone_warning, name, last_used_at, created_at, updated_at
			FROM webauthn_credentials 
			WHERE user_id = ?
			ORDER BY created_at DESC`
		args = []interface{}{userID}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to query credentials", err)
	}
	defer rows.Close()

	var credentials []*models.WebAuthnCredential
	for rows.Next() {
		credential := &models.WebAuthnCredential{}
		var transportValue interface{}
		var transportStrs []string
		var transportStr string
		
		// Prepare transport scanning based on database type
		if r.db.DriverName() == "postgres" {
			transportValue = pq.Array(&transportStrs)
		} else {
			transportValue = &transportStr
		}
		
		err := rows.Scan(
			&credential.ID,
			&credential.UserID,
			&credential.CredentialID,
			&credential.PublicKey,
			&credential.AttestationType,
			transportValue,
			&credential.Flags.UserPresent,
			&credential.Flags.UserVerified,
			&credential.Flags.BackupEligible,
			&credential.Flags.BackupState,
			&credential.SignCount,
			&credential.CloneWarning,
			&credential.Name,
			&credential.LastUsedAt,
			&credential.CreatedAt,
			&credential.UpdatedAt,
		)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan credential", err)
		}

		// Convert transport data back to slice of AuthenticatorTransport
		if r.db.DriverName() == "postgres" {
			// PostgreSQL: convert from array
			credential.Transport = make([]models.AuthenticatorTransport, len(transportStrs))
			for i, ts := range transportStrs {
				credential.Transport[i] = models.AuthenticatorTransport(ts)
			}
		} else {
			// SQLite: convert from comma-separated string
			credential.Transport = models.StringToTransports(transportStr)
			
			// For SQLite, we need to filter in application code
			hasMatchingTransport := false
			for _, credTransport := range credential.Transport {
				for _, filterTransport := range transports {
					if credTransport == filterTransport {
						hasMatchingTransport = true
						break
					}
				}
				if hasMatchingTransport {
					break
				}
			}
			if !hasMatchingTransport {
				continue // Skip this credential
			}
		}

		credentials = append(credentials, credential)
	}

	return credentials, nil
}

// UpdateCredentialSignCount updates the sign count for a credential
func (r *postgresWebAuthnRepository) UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE webauthn_credentials 
		SET sign_count = $1, updated_at = $2
		WHERE credential_id = $3`

	fmt.Printf("DEBUG REPO: Executing sign count update - ID: %x, SignCount: %d\n", credentialID, signCount)
	result, err := r.db.ExecContext(ctx, query, signCount, time.Now(), credentialID)
	if err != nil {
		fmt.Printf("ERROR REPO: SQL execution failed: %v\n", err)
		return NewRepositoryError(ErrRepositoryInternal, "Failed to update sign count", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Printf("ERROR REPO: Failed to get rows affected: %v\n", err)
		return NewRepositoryError(ErrRepositoryInternal, "Failed to get rows affected", err)
	}

	fmt.Printf("DEBUG REPO: Sign count update affected %d rows\n", rowsAffected)
	if rowsAffected == 0 {
		fmt.Printf("ERROR REPO: No rows affected - credential not found with ID: %x\n", credentialID)
		return NewRepositoryError(ErrRepositoryNotFound, "Credential not found", nil)
	}

	return nil
}

// UpdateCredentialLastUsed updates the last used timestamp for a credential
func (r *postgresWebAuthnRepository) UpdateCredentialLastUsed(ctx context.Context, credentialID []byte, lastUsed time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		UPDATE webauthn_credentials 
		SET last_used_at = $1, updated_at = $2
		WHERE credential_id = $3`

	result, err := r.db.ExecContext(ctx, query, lastUsed, time.Now(), credentialID)
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to update last used", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to get rows affected", err)
	}

	if rowsAffected == 0 {
		return NewRepositoryError(ErrRepositoryNotFound, "Credential not found", nil)
	}

	return nil
}

// GetCredentialCount returns the number of credentials for a user
func (r *postgresWebAuthnRepository) GetCredentialCount(ctx context.Context, userID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if err := validateUUID(userID); err != nil {
		return 0, NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", err)
	}

	// Use database-agnostic placeholder
	query := `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`
	if r.db.DriverName() == "postgres" {
		query = `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1`
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, NewRepositoryError(ErrRepositoryInternal, "Failed to count credentials", err)
	}

	return count, nil
}

// GetCredentialsByTransport returns credentials using a specific transport method
func (r *postgresWebAuthnRepository) GetCredentialsByTransport(ctx context.Context, transport models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type,
			   transport, user_present, user_verified, backup_eligible, backup_state,
			   sign_count, clone_warning, name, last_used_at, created_at, updated_at
		FROM webauthn_credentials 
		WHERE transport LIKE $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, "%"+string(transport)+"%")
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to query credentials by transport", err)
	}
	defer rows.Close()

	var credentials []*models.WebAuthnCredential
	for rows.Next() {
		credential := &models.WebAuthnCredential{}
		var transportStr string
		
		err := rows.Scan(
			&credential.ID,
			&credential.UserID,
			&credential.CredentialID,
			&credential.PublicKey,
			&credential.AttestationType,
			&transportStr,
			&credential.Flags.UserPresent,
			&credential.Flags.UserVerified,
			&credential.Flags.BackupEligible,
			&credential.Flags.BackupState,
			&credential.SignCount,
			&credential.CloneWarning,
			&credential.Name,
			&credential.LastUsedAt,
			&credential.CreatedAt,
			&credential.UpdatedAt,
		)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan credential", err)
		}

		credential.Transport = models.StringToTransports(transportStr)
		credentials = append(credentials, credential)
	}

	return credentials, nil
}

// CleanupExpiredCredentials removes credentials older than the retention period
func (r *postgresWebAuthnRepository) CleanupExpiredCredentials(ctx context.Context, retentionPeriod time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cutoffTime := time.Now().Add(-retentionPeriod)
	
	query := `DELETE FROM webauthn_credentials WHERE created_at < $1`

	result, err := r.db.ExecContext(ctx, query, cutoffTime)
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to cleanup expired credentials", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return NewRepositoryError(ErrRepositoryInternal, "Failed to get rows affected", err)
	}

	// Log the number of credentials cleaned up (could be added to logging system)
	_ = rowsAffected

	return nil
}

// GetCredentialStatistics returns statistics about stored credentials
func (r *postgresWebAuthnRepository) GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	stats := &CredentialStatistics{
		CredentialsByTransport:   make(map[models.AuthenticatorTransport]int),
		CredentialsByAttestation: make(map[string]int),
		MostActiveUsers:          make([]UserCredentialStats, 0),
	}

	// Get total credentials
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webauthn_credentials").Scan(&stats.TotalCredentials)
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get total credentials", err)
	}

	// Get credentials by attestation type
	rows, err := r.db.QueryContext(ctx, "SELECT attestation_type, COUNT(*) FROM webauthn_credentials GROUP BY attestation_type")
	if err != nil {
		return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get attestation statistics", err)
	}
	defer rows.Close()

	for rows.Next() {
		var attestationType string
		var count int
		if err := rows.Scan(&attestationType, &count); err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to scan attestation stats", err)
		}
		stats.CredentialsByAttestation[attestationType] = count
	}

	// Get time-based statistics
	now := time.Now()
	timeQueries := map[string]time.Time{
		"24h":   now.Add(-24 * time.Hour),
		"week":  now.Add(-7 * 24 * time.Hour),
		"month": now.Add(-30 * 24 * time.Hour),
	}

	for period, since := range timeQueries {
		var count int
		err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webauthn_credentials WHERE created_at >= $1", since).Scan(&count)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, fmt.Sprintf("Failed to get %s statistics", period), err)
		}

		switch period {
		case "24h":
			stats.CreatedInLast24Hours = count
		case "week":
			stats.CreatedInLastWeek = count
		case "month":
			stats.CreatedInLastMonth = count
		}
	}

	// Calculate average credentials per user
	if stats.TotalCredentials > 0 {
		var userCount int
		err := r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT user_id) FROM webauthn_credentials").Scan(&userCount)
		if err != nil {
			return nil, NewRepositoryError(ErrRepositoryInternal, "Failed to get user count", err)
		}
		if userCount > 0 {
			stats.AvgCredentialsPerUser = float64(stats.TotalCredentials) / float64(userCount)
		}
	}

	return stats, nil
}

// Helper function to validate UUID v4 format
func validateUUID(id string) error {
	if id == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	// General UUID pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// where x is any hexadecimal digit
	uuidPattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	matched, err := regexp.MatchString(uuidPattern, id)
	if err != nil {
		return fmt.Errorf("UUID validation error: %v", err)
	}
	
	if !matched {
		return fmt.Errorf("invalid UUID format: %s", id)
	}
	
	return nil
}