package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/dqx0/glen/user-service/internal/models"
	"github.com/dqx0/glen/user-service/internal/repository"
)

var (
	ErrUsernameExists                = errors.New("username already exists")
	ErrEmailExists                   = errors.New("email already exists")
	ErrInvalidCredentials            = errors.New("invalid credentials")
	ErrPasswordAuthNotAvailable      = errors.New("password authentication not available")
	ErrUserNotFound                  = errors.New("user not found")
)

// UserRepositoryInterface はリポジトリのインターフェース
type UserRepositoryInterface interface {
	Create(ctx context.Context, user *models.User) error
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id string) error
}

type UserService struct {
	userRepo UserRepositoryInterface
}

func NewUserService(userRepo UserRepositoryInterface) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// Register は新しいユーザーを登録する
func (s *UserService) Register(ctx context.Context, username, email, password string) (*models.User, error) {
	// ユーザー名の重複チェック
	existingUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil && !errors.Is(err, repository.ErrUserNotFound) {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}
	if existingUser != nil {
		return nil, ErrUsernameExists
	}

	// メールアドレスの重複チェック（メールが提供された場合）
	if email != "" {
		existingUser, err := s.userRepo.GetByEmail(ctx, email)
		if err != nil && !errors.Is(err, repository.ErrUserNotFound) {
			return nil, fmt.Errorf("failed to check email: %w", err)
		}
		if existingUser != nil {
			return nil, ErrEmailExists
		}
	}

	// ユーザー作成
	user, err := models.NewUser(username, email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// データベースに保存
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return user, nil
}

// Login はユーザー名とパスワードでログインする
func (s *UserService) Login(ctx context.Context, username, password string) (*models.User, error) {
	// ユーザーを取得
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// パスワードが設定されていない場合（WebAuthnのみ）
	if user.PasswordHash == "" {
		return nil, ErrPasswordAuthNotAvailable
	}

	// パスワード検証
	if !user.ValidatePassword(password) {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// GetUser はユーザー名でユーザーを取得する
func (s *UserService) GetUser(ctx context.Context, username string) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetUserByID はIDでユーザーを取得する
func (s *UserService) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// UpdatePassword はユーザーのパスワードを更新する
func (s *UserService) UpdatePassword(ctx context.Context, username, newPassword string) error {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := user.UpdatePassword(newPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	return nil
}

// VerifyEmail はユーザーのメールアドレスを検証済みにする
func (s *UserService) VerifyEmail(ctx context.Context, username string) error {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	user.SetEmailVerified(true)

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	return nil
}