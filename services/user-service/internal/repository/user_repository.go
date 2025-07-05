package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/dqx0/glen/user-service/internal/models"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserExists   = errors.New("username already exists")
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, email_verified, status, created_at, updated_at, organization_id, parent_user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.EmailVerified,
		user.Status,
		user.CreatedAt,
		user.UpdatedAt,
		user.OrganizationID,
		user.ParentUserID,
	)
	
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserExists
		}
		return err
	}
	
	return nil
}

func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, email_verified, status, created_at, updated_at, organization_id, parent_user_id
		FROM users
		WHERE username = ?
	`
	
	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.OrganizationID,
		&user.ParentUserID,
	)
	
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, email_verified, status, created_at, updated_at, organization_id, parent_user_id
		FROM users
		WHERE email = ?
	`
	
	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.OrganizationID,
		&user.ParentUserID,
	)
	
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	
	return user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, email_verified, status, created_at, updated_at, organization_id, parent_user_id
		FROM users
		WHERE id = ?
	`
	
	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.OrganizationID,
		&user.ParentUserID,
	)
	
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET username = ?, email = ?, password_hash = ?, email_verified = ?, status = ?, updated_at = ?, organization_id = ?, parent_user_id = ?
		WHERE id = ?
	`
	
	result, err := r.db.ExecContext(ctx, query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.EmailVerified,
		user.Status,
		user.UpdatedAt,
		user.OrganizationID,
		user.ParentUserID,
		user.ID,
	)
	
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	
	return nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	
	return nil
}