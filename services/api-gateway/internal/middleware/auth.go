package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// AuthMiddleware は認証を処理するミドルウェア
type AuthMiddleware struct {
	authServiceURL string
}

// NewAuthMiddleware は新しいAuthMiddlewareを作成する
func NewAuthMiddleware(authServiceURL string) *AuthMiddleware {
	return &AuthMiddleware{
		authServiceURL: authServiceURL,
	}
}

// Handle は認証を確認してからハンドラーを実行する
func (a *AuthMiddleware) Handle(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authorizationヘッダーの確認
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "authorization header required")
			return
		}
		
		// Bearer token or API key の判定
		if strings.HasPrefix(authHeader, "Bearer ") {
			// JWT トークンの処理
			token := authHeader[7:] // "Bearer " を除去
			if !a.validateJWTToken(token) {
				a.writeUnauthorizedResponse(w, "invalid JWT token")
				return
			}
		} else if strings.HasPrefix(authHeader, "ApiKey ") {
			// API キーの処理
			apiKey := authHeader[7:] // "ApiKey " を除去
			if !a.validateAPIKey(apiKey) {
				a.writeUnauthorizedResponse(w, "invalid API key")
				return
			}
		} else {
			a.writeUnauthorizedResponse(w, "unsupported authorization type")
			return
		}
		
		// 認証成功 - コンテキストに認証情報を追加
		ctx := context.WithValue(r.Context(), "authenticated", true)
		r = r.WithContext(ctx)
		
		// ユーザーIDをヘッダーに設定（プロキシ用）
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := authHeader[7:]
			if userID := extractUserIDFromJWT(token); userID != "" {
				r.Header.Set("X-User-ID", userID)
			}
		}
		
		// 次のハンドラーを実行
		handler(w, r)
	}
}

// validateJWTToken はJWTトークンを検証する
func (a *AuthMiddleware) validateJWTToken(token string) bool {
	// 簡易的な実装：実際には auth-service に検証リクエストを送信
	// ここでは基本的な形式チェックのみ
	if len(token) < 10 {
		return false
	}
	
	// トークンが適切な形式かチェック（JWT は通常 xxx.yyy.zzz の形式）
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("Invalid JWT format: expected 3 parts, got %d", len(parts))
		return false
	}
	
	// 実際のアプリケーションでは、auth-service に検証リクエストを送信
	// validateURL := fmt.Sprintf("%s/api/v1/auth/validate", a.authServiceURL)
	// ... HTTP リクエストの実装
	
	// 開発段階では true を返す
	return true
}

// JWTPayload はJWTのペイロード構造
type JWTPayload struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Exp      int64  `json:"exp"`
}

// extractUserIDFromJWT はJWTトークンからユーザーIDを抽出する
func extractUserIDFromJWT(token string) string {
	// JWTは3つの部分に分かれている: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("Invalid JWT format: expected 3 parts, got %d", len(parts))
		return ""
	}

	// ペイロード部分をデコード
	payload := parts[1]
	
	// Base64のパディングを修正
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Base64デコード
	payloadBytes, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("Failed to decode JWT payload: %v", err)
		return ""
	}

	// JSONをパース
	var jwtPayload JWTPayload
	if err := json.Unmarshal(payloadBytes, &jwtPayload); err != nil {
		log.Printf("Failed to parse JWT payload: %v", err)
		return ""
	}

	log.Printf("Extracted user_id from JWT: %s", jwtPayload.UserID)
	return jwtPayload.UserID
}

// validateAPIKey はAPIキーを検証する
func (a *AuthMiddleware) validateAPIKey(apiKey string) bool {
	// 簡易的な実装：実際には auth-service に検証リクエストを送信
	if len(apiKey) < 32 {
		return false
	}
	
	// 実際のアプリケーションでは、auth-service に検証リクエストを送信
	// validateURL := fmt.Sprintf("%s/api/v1/auth/validate-api-key", a.authServiceURL)
	// ... HTTP リクエストの実装
	
	// 開発段階では true を返す
	return true
}

// writeUnauthorizedResponse は認証エラーレスポンスを書き込む
func (a *AuthMiddleware) writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	
	response := `{"success":false,"error":"` + message + `"}`
	w.Write([]byte(response))
}

// RequireAPIKey はAPIキー認証のみを要求するミドルウェア
func (a *AuthMiddleware) RequireAPIKey(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "API key required")
			return
		}
		
		if !strings.HasPrefix(authHeader, "ApiKey ") {
			a.writeUnauthorizedResponse(w, "API key format: 'ApiKey <your-key>'")
			return
		}
		
		apiKey := authHeader[7:]
		if !a.validateAPIKey(apiKey) {
			a.writeUnauthorizedResponse(w, "invalid API key")
			return
		}
		
		// 認証成功
		ctx := context.WithValue(r.Context(), "authenticated", true)
		ctx = context.WithValue(ctx, "auth_type", "api_key")
		r = r.WithContext(ctx)
		
		handler(w, r)
	}
}

// RequireJWT はJWT認証のみを要求するミドルウェア
func (a *AuthMiddleware) RequireJWT(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "JWT token required")
			return
		}
		
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.writeUnauthorizedResponse(w, "JWT format: 'Bearer <your-token>'")
			return
		}
		
		token := authHeader[7:]
		if !a.validateJWTToken(token) {
			a.writeUnauthorizedResponse(w, "invalid JWT token")
			return
		}
		
		// 認証成功
		ctx := context.WithValue(r.Context(), "authenticated", true)
		ctx = context.WithValue(ctx, "auth_type", "jwt")
		r = r.WithContext(ctx)
		
		handler(w, r)
	}
}