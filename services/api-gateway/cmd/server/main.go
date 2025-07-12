package main

import (
	"log"
	"net/http"
	"os"

	"github.com/dqx0/glen/api-gateway/internal/handlers"
	"github.com/dqx0/glen/api-gateway/internal/middleware"
	"github.com/dqx0/glen/api-gateway/internal/service"
)

func main() {
	// サービス設定の読み込み
	config := loadConfig()

	// サービスプロキシの作成
	proxyConfig := &service.Config{
		UserService:   config.UserService,
		AuthService:   config.AuthService,
		SocialService: config.SocialService,
	}
	serviceProxy := service.NewServiceProxy(proxyConfig)

	// ハンドラーの作成
	gatewayHandler := handlers.NewGatewayHandler(serviceProxy)

	// ミドルウェアの設定
	corsMiddleware := middleware.NewCORSMiddleware()
	authMiddleware := middleware.NewAuthMiddleware(config.AuthService)
	loggingMiddleware := middleware.NewLoggingMiddleware()

	// ルーターの設定
	mux := http.NewServeMux()

	// 認証が不要なエンドポイント
	mux.HandleFunc("/health", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("gateway OK"))
	}))

	// ユーザー関連（認証不要 - 登録・ログイン）
	mux.HandleFunc("/api/v1/users/register", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToUserService)))
	mux.HandleFunc("/api/v1/users/login", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToUserService)))

	// 認証関連（認証不要 - トークン発行・リフレッシュ）
	mux.HandleFunc("/api/v1/auth/login", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/auth/refresh", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))

	// WebAuthn関連（認証不要 - 登録・認証フロー）
	mux.HandleFunc("/api/v1/webauthn/register/start", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/webauthn/register/finish", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/webauthn/authenticate/start", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/webauthn/authenticate/finish", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))

	// ソーシャルログイン（認証不要 - OAuth2フロー）
	mux.HandleFunc("/api/v1/social/authorize", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToSocialService)))
	mux.HandleFunc("/api/v1/social/login", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToSocialService)))
	mux.HandleFunc("/api/v1/social/providers", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToSocialService)))
	
	// ソーシャルアカウント連携（認証必要）
	mux.HandleFunc("/api/v1/social/callback", loggingMiddleware.Handle(corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToSocialService))))

	// 認証が必要なエンドポイント
	// ユーザー情報取得（特定のパス）
	mux.HandleFunc("/api/v1/users/", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" || r.URL.Path == "/api/v1/users/" {
			corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToUserService))(w, r)
		} else {
			corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToUserService))(w, r)
		}
	}))

	// 認証サービス（特定のパス以外）
	mux.HandleFunc("/api/v1/auth/", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		// 認証不要のパスをチェック
		path := r.URL.Path
		if path == "/api/v1/auth/login" || path == "/api/v1/auth/refresh" {
			http.NotFound(w, r) // 上記で処理済み
			return
		}
		corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToAuthService))(w, r)
	}))

	// WebAuthn認証器管理（特定のパス以外）
	mux.HandleFunc("/api/v1/webauthn/", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// 認証不要のパスをチェック
		if path == "/api/v1/webauthn/register/start" || 
		   path == "/api/v1/webauthn/register/finish" ||
		   path == "/api/v1/webauthn/authenticate/start" ||
		   path == "/api/v1/webauthn/authenticate/finish" {
			http.NotFound(w, r) // 上記で処理済み
			return
		}
		corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToAuthService))(w, r)
	}))

	// ソーシャルアカウント管理（特定のパス以外）
	mux.HandleFunc("/api/v1/social/", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// 認証不要のパスをチェック
		if path == "/api/v1/social/authorize" || 
		   path == "/api/v1/social/login" ||
		   path == "/api/v1/social/callback" ||
		   path == "/api/v1/social/providers" {
			http.NotFound(w, r) // 上記で処理済み
			return
		}
		corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToSocialService))(w, r)
	}))

	// OAuth2関連（認証必要）
	mux.HandleFunc("/api/v1/oauth2/", loggingMiddleware.Handle(corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToAuthService))))

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("API Gateway starting on port %s", port)
	log.Printf("Proxying to:")
	log.Printf("  User Service: %s", config.UserService)
	log.Printf("  Auth Service: %s", config.AuthService)
	log.Printf("  Social Service: %s", config.SocialService)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// Config はAPI Gatewayの設定を保持する
type Config struct {
	UserService   string
	AuthService   string
	SocialService string
}

func loadConfig() *Config {
	return &Config{
		UserService:   getEnvOrDefault("USER_SERVICE_URL", "http://localhost:8082"),
		AuthService:   getEnvOrDefault("AUTH_SERVICE_URL", "http://localhost:8081"),
		SocialService: getEnvOrDefault("SOCIAL_SERVICE_URL", "http://localhost:8083"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
