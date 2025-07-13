package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// CORSOrigin represents a dynamic CORS origin entry
type CORSOrigin struct {
	ID            int       `db:"id"`
	Origin        string    `db:"origin"`
	OAuth2ClientID string   `db:"oauth2_client_id"`
	CreatedAt     time.Time `db:"created_at"`
}

// CORSRepository defines the interface for CORS origin persistence
type CORSRepository interface {
	AddOrigin(ctx context.Context, origin, clientID string) error
	RemoveOrigin(ctx context.Context, origin string) error
	GetAllOrigins(ctx context.Context) ([]string, error)
	RemoveOriginsByClientID(ctx context.Context, clientID string) error
	GetOriginsByClientID(ctx context.Context, clientID string) ([]string, error)
}

// PostgreSQLCORSRepository implements CORSRepository using PostgreSQL
type PostgreSQLCORSRepository struct {
	db *sqlx.DB
}

// NewCORSRepository creates a new CORS repository
func NewCORSRepository(db *sql.DB) CORSRepository {
	return &PostgreSQLCORSRepository{
		db: sqlx.NewDb(db, "postgres"),
	}
}

// AddOrigin adds a dynamic CORS origin to the database
func (r *PostgreSQLCORSRepository) AddOrigin(ctx context.Context, origin, clientID string) error {
	if origin == "" {
		return errors.New("origin cannot be empty")
	}
	if clientID == "" {
		return errors.New("client ID cannot be empty")
	}

	query := `
		INSERT INTO cors_dynamic_origins (origin, oauth2_client_id, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (origin, oauth2_client_id) DO NOTHING
	`
	
	_, err := r.db.ExecContext(ctx, query, origin, clientID)
	if err != nil {
		return fmt.Errorf("failed to add CORS origin: %w", err)
	}

	return nil
}

// RemoveOrigin removes all instances of a CORS origin from the database
func (r *PostgreSQLCORSRepository) RemoveOrigin(ctx context.Context, origin string) error {
	if origin == "" {
		return errors.New("origin cannot be empty")
	}

	query := `DELETE FROM cors_dynamic_origins WHERE origin = $1`
	
	result, err := r.db.ExecContext(ctx, query, origin)
	if err != nil {
		return fmt.Errorf("failed to remove CORS origin: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Log the number of rows affected (for monitoring)
	if rowsAffected > 0 {
		// Note: In production, this would use structured logging
		fmt.Printf("CORS Repository: Removed %d instances of origin: %s\n", rowsAffected, origin)
	}

	return nil
}

// GetAllOrigins retrieves all unique CORS origins from the database
func (r *PostgreSQLCORSRepository) GetAllOrigins(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT origin FROM cors_dynamic_origins ORDER BY origin`
	
	var origins []string
	err := r.db.SelectContext(ctx, &origins, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all CORS origins: %w", err)
	}

	return origins, nil
}

// RemoveOriginsByClientID removes all CORS origins associated with a specific OAuth2 client
func (r *PostgreSQLCORSRepository) RemoveOriginsByClientID(ctx context.Context, clientID string) error {
	if clientID == "" {
		return errors.New("client ID cannot be empty")
	}

	query := `DELETE FROM cors_dynamic_origins WHERE oauth2_client_id = $1`
	
	result, err := r.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to remove CORS origins for client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Log the cleanup operation
	if rowsAffected > 0 {
		fmt.Printf("CORS Repository: Removed %d origins for client: %s\n", rowsAffected, clientID)
	}

	return nil
}

// GetOriginsByClientID retrieves all CORS origins associated with a specific OAuth2 client
func (r *PostgreSQLCORSRepository) GetOriginsByClientID(ctx context.Context, clientID string) ([]string, error) {
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}

	query := `SELECT DISTINCT origin FROM cors_dynamic_origins WHERE oauth2_client_id = $1 ORDER BY origin`
	
	var origins []string
	err := r.db.SelectContext(ctx, &origins, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get CORS origins for client: %w", err)
	}

	return origins, nil
}

// GetOriginDetails retrieves detailed information about CORS origins (for monitoring/debugging)
func (r *PostgreSQLCORSRepository) GetOriginDetails(ctx context.Context) ([]CORSOrigin, error) {
	query := `
		SELECT id, origin, oauth2_client_id, created_at 
		FROM cors_dynamic_origins 
		ORDER BY created_at DESC
	`
	
	var origins []CORSOrigin
	err := r.db.SelectContext(ctx, &origins, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get CORS origin details: %w", err)
	}

	return origins, nil
}

// GetOriginCount returns the total number of dynamic CORS origins
func (r *PostgreSQLCORSRepository) GetOriginCount(ctx context.Context) (int, error) {
	query := `SELECT COUNT(DISTINCT origin) FROM cors_dynamic_origins`
	
	var count int
	err := r.db.GetContext(ctx, &count, query)
	if err != nil {
		return 0, fmt.Errorf("failed to get CORS origin count: %w", err)
	}

	return count, nil
}

// CleanupOrphanedOrigins removes CORS origins that are no longer associated with valid OAuth2 clients
func (r *PostgreSQLCORSRepository) CleanupOrphanedOrigins(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM cors_dynamic_origins 
		WHERE oauth2_client_id NOT IN (
			SELECT client_id FROM oauth2_clients
		)
	`
	
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup orphaned CORS origins: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// ValidateOrigin checks if an origin is valid and safe to add
func (r *PostgreSQLCORSRepository) ValidateOrigin(origin string) error {
	if origin == "" {
		return errors.New("origin cannot be empty")
	}

	// Additional validation could be added here:
	// - URL parsing
	// - Domain validation
	// - Blacklist checking
	// - Length limits

	return nil
}

// GetOriginStats returns statistics about CORS origins
type OriginStats struct {
	TotalOrigins     int `json:"total_origins"`
	TotalClients     int `json:"total_clients"`
	OriginsPerClient map[string]int `json:"origins_per_client"`
}

func (r *PostgreSQLCORSRepository) GetOriginStats(ctx context.Context) (*OriginStats, error) {
	// Get total unique origins
	totalOrigins, err := r.GetOriginCount(ctx)
	if err != nil {
		return nil, err
	}

	// Get total clients with origins
	var totalClients int
	clientCountQuery := `SELECT COUNT(DISTINCT oauth2_client_id) FROM cors_dynamic_origins`
	err = r.db.GetContext(ctx, &totalClients, clientCountQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get client count: %w", err)
	}

	// Get origins per client
	originsPerClientQuery := `
		SELECT oauth2_client_id, COUNT(DISTINCT origin) as origin_count
		FROM cors_dynamic_origins 
		GROUP BY oauth2_client_id
		ORDER BY origin_count DESC
	`
	
	type clientOriginCount struct {
		ClientID    string `db:"oauth2_client_id"`
		OriginCount int    `db:"origin_count"`
	}

	var clientCounts []clientOriginCount
	err = r.db.SelectContext(ctx, &clientCounts, originsPerClientQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get origins per client: %w", err)
	}

	originsPerClient := make(map[string]int)
	for _, cc := range clientCounts {
		originsPerClient[cc.ClientID] = cc.OriginCount
	}

	return &OriginStats{
		TotalOrigins:     totalOrigins,
		TotalClients:     totalClients,
		OriginsPerClient: originsPerClient,
	}, nil
}