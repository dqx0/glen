package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dqx0/glen/api-gateway/internal/handlers"
	"github.com/dqx0/glen/api-gateway/internal/middleware"
	"github.com/dqx0/glen/api-gateway/internal/repository"
	"github.com/dqx0/glen/api-gateway/internal/service"
	
	_ "github.com/lib/pq"
)

func main() {
	// サービス設定の読み込み
	config := loadConfig()

	// データベース接続の初期化（CORS永続化用）
	var corsMiddleware *middleware.CORSMiddleware
	if config.DatabaseURL != "" {
		db, err := initDatabase(config.DatabaseURL)
		if err != nil {
			log.Printf("Warning: Failed to initialize database for CORS persistence: %v", err)
			log.Printf("Continuing with in-memory CORS only")
			corsMiddleware = middleware.NewCORSMiddleware(config.AuthService)
		} else {
			defer db.Close()
			
			// CORS Repository の作成
			corsRepo := repository.NewCORSRepository(db)
			
			// CORS Middleware を永続化機能付きで作成
			corsMiddleware = middleware.NewCORSMiddlewareWithRepository(config.AuthService, corsRepo)
			
			// サービス起動時にCORS設定を同期
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			
			if err := corsMiddleware.LoadPersistedOrigins(ctx); err != nil {
				log.Printf("Warning: Failed to load persisted CORS origins: %v", err)
				log.Printf("Continuing with current configuration")
			} else {
				log.Printf("Successfully loaded persisted CORS origins from database")
			}
		}
	} else {
		log.Printf("No database URL configured, using in-memory CORS only")
		corsMiddleware = middleware.NewCORSMiddleware(config.AuthService)
	}

	// サービスプロキシの作成
	proxyConfig := &service.Config{
		UserService:   config.UserService,
		AuthService:   config.AuthService,
		SocialService: config.SocialService,
	}
	serviceProxy := service.NewServiceProxy(proxyConfig)

	// ハンドラーの作成
	gatewayHandler := handlers.NewGatewayHandler(serviceProxy)

	// その他のミドルウェアの設定
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

	// OAuth2 Handler (Gateway が制御)
	oauth2Handler := handlers.NewOAuth2Handler(config.AuthService)
	
	// CORS管理ハンドラー（内部サービス用）
	corsHandler := handlers.NewCORSHandler(corsMiddleware)
	
	// OAuth2 authorize エンドポイント（Gateway で処理）
	mux.HandleFunc("/api/v1/oauth2/authorize", loggingMiddleware.Handle(corsMiddleware.Handle(oauth2Handler.HandleAuthorize)))
	mux.HandleFunc("/api/v1/oauth2/token", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/oauth2/revoke", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	mux.HandleFunc("/api/v1/oauth2/introspect", loggingMiddleware.Handle(corsMiddleware.Handle(gatewayHandler.ProxyToAuthService)))
	
	// OAuth2 クライアント管理（認証必要）
	mux.HandleFunc("/api/v1/oauth2/", loggingMiddleware.Handle(corsMiddleware.Handle(authMiddleware.Handle(gatewayHandler.ProxyToAuthService))))

	// 内部サービス用CORS管理エンドポイント（認証不要・内部サービスのみ）
	mux.HandleFunc("/internal/cors/origins", loggingMiddleware.Handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			corsHandler.UpdateOrigins(w, r)
		case http.MethodGet:
			corsHandler.GetOrigins(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))

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
	DatabaseURL   string
}

func loadConfig() *Config {
	return &Config{
		UserService:   getEnvOrDefault("USER_SERVICE_URL", "http://localhost:8082"),
		AuthService:   getEnvOrDefault("AUTH_SERVICE_URL", "http://localhost:8081"),
		SocialService: getEnvOrDefault("SOCIAL_SERVICE_URL", "http://localhost:8083"),
		DatabaseURL:   os.Getenv("DATABASE_URL"), // Optional database for CORS persistence
	}
}

// initDatabase initializes the database connection for CORS persistence
func initDatabase(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}
	
	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	
	// Set connection pool parameters
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	log.Printf("Database connection established for CORS persistence")
	return db, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
