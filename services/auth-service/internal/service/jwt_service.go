package service

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// JWT設定
	AccessTokenDuration = 15 * time.Minute
	Issuer             = "glen-auth-service"
	Audience           = "glen-services"
)

var (
	ErrInvalidUserID   = errors.New("invalid user ID")
	ErrInvalidUsername = errors.New("invalid username")
	ErrEmptyScopes     = errors.New("empty scopes")
	ErrInvalidKeys     = errors.New("invalid keys")
	ErrInvalidToken    = errors.New("invalid token")
)

// Claims はJWTクレーム構造体
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Scopes   []string `json:"scopes"`
	jwt.RegisteredClaims
}

// JWTService はJWT関連の操作を提供する
type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewJWTService は新しいJWTServiceを作成する
func NewJWTService(privateKey, publicKey interface{}) (*JWTService, error) {
	var privKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey
	
	// Private keyの変換
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		privKey = k
	case nil:
		return nil, ErrInvalidKeys
	default:
		return nil, ErrInvalidKeys
	}
	
	// Public keyの変換
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		pubKey = k
	case nil:
		return nil, ErrInvalidKeys
	default:
		return nil, ErrInvalidKeys
	}
	
	return &JWTService{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// GenerateAccessToken はアクセストークンを生成する
func (j *JWTService) GenerateAccessToken(userID, username string, scopes []string) (string, string, error) {
	if userID == "" {
		return "", "", ErrInvalidUserID
	}
	
	if username == "" {
		return "", "", ErrInvalidUsername
	}
	
	if len(scopes) == 0 {
		return "", "", ErrEmptyScopes
	}
	
	now := time.Now()
	jwtID := uuid.New().String()
	
	claims := Claims{
		UserID:   userID,
		Username: username,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jwtID,
			Issuer:    Issuer,
			Audience:  []string{Audience},
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	
	tokenString, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}
	
	return tokenString, jwtID, nil
}

// ValidateToken はトークンを検証してクレームを返す
func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}
	
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// 署名方式の確認
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	
	return claims, nil
}

// GenerateTestKeyPair はテスト用のRSA鍵ペアを生成する
func GenerateTestKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	publicKey := &privateKey.PublicKey
	
	return privateKey, publicKey, nil
}