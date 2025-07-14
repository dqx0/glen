package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/dqx0/glen/auth-service/internal/handlers"
	"github.com/dqx0/glen/auth-service/internal/repository"
	"github.com/dqx0/glen/auth-service/internal/service"
	"github.com/dqx0/glen/auth-service/internal/webauthn"
	"github.com/dqx0/glen/auth-service/internal/webauthn/config"
	webauthnMiddleware "github.com/dqx0/glen/auth-service/internal/webauthn/middleware"

	// OAuth2 imports
	oauth2Database "github.com/dqx0/glen/auth-service/internal/oauth2/database"
	oauth2Handlers "github.com/dqx0/glen/auth-service/internal/oauth2/handlers"
	oauth2Repository "github.com/dqx0/glen/auth-service/internal/oauth2/repository"
	oauth2Service "github.com/dqx0/glen/auth-service/internal/oauth2/service"
)

func main() {
	// データベース接続 (SQL)
	db, err := connectDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// データベース接続 (SQLx)
	sqlxDB := sqlx.NewDb(db, "postgres")

	// Redis接続
	redisClient := redis.NewClient(&redis.Options{
		Addr:     getRedisAddr(),
		Password: "",
		DB:       0,
	})

	// RSA鍵ペアの取得（実際の環境では環境変数やファイルから読み込み）
	privateKey, publicKey, err := service.GenerateTestKeyPair()
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

	// 依存関係の構築
	tokenRepo := repository.NewTokenRepository(db)
	jwtService, err := service.NewJWTService(privateKey, publicKey)
	if err != nil {
		log.Fatal("Failed to create JWT service:", err)
	}
	authService := service.NewAuthService(tokenRepo, jwtService)
	authHandler := handlers.NewAuthHandler(authService)

	// WebAuthn設定
	webAuthnConfig := &config.WebAuthnConfig{
		RPDisplayName: "Glen Authentication System",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:5173", "http://localhost:3000", "https://glen.dqx0.com"},
		RPIcon:        "",
		Timeout:       60000, // 60 seconds
		Debug:         true,
	}

	// WebAuthnモジュールの作成
	webAuthnModule, err := webauthn.NewWebAuthnModule(sqlxDB, redisClient, webAuthnConfig)
	if err != nil {
		log.Fatal("Failed to create WebAuthn module:", err)
	}

	// Database migration for WebAuthn tables
	migration := webauthn.NewDatabaseMigration(sqlxDB)
	if err := migration.CreateWebAuthnTables(); err != nil {
		log.Printf("Warning: Failed to create WebAuthn tables: %v", err)
	}

	// OAuth2 database migration
	ctx := context.Background()
	if err := oauth2Database.ApplyAllOAuth2Migrations(ctx, db); err != nil {
		log.Printf("Warning: Failed to apply OAuth2 migrations: %v", err)
	} else {
		log.Println("OAuth2 database migrations applied successfully")
	}

	// WebAuthn JWT設定で新しいハンドラーを作成
	webAuthnJWTConfig := webauthnMiddleware.NewJWTConfig(jwtService)
	webAuthnHandler := webauthn.NewWebAuthnHandlerWithJWT(webAuthnModule.Service, webAuthnJWTConfig)

	// OAuth2 dependencies
	oauth2Repo := oauth2Repository.NewOAuth2Repository(db)

	// CORS通知機能の設定
	gatewayURL := getEnvOrDefault("API_GATEWAY_URL", "http://localhost:8080")
	corsNotifier := oauth2Service.NewHTTPCORSNotifier(gatewayURL)

	oauth2Svc := oauth2Service.NewOAuth2ServiceWithCORS(oauth2Repo, corsNotifier)
	oauth2Handler := oauth2Handlers.NewOAuth2Handler(oauth2Svc)

	// Chi ルーターの設定
	r := chi.NewRouter()

	// ミドルウェア
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	// CORS設定 - API Gateway経由でアクセスされるため無効化
	// API Gatewayで統一的にCORS処理を行う

	// APIルート
	r.Route("/api/v1", func(r chi.Router) {
		// 認証エンドポイント
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.RefreshToken)
			r.Post("/api-keys", authHandler.CreateAPIKey)
			r.Post("/revoke", authHandler.RevokeToken)
			r.Get("/tokens", authHandler.ListTokens)
			r.Post("/validate-api-key", authHandler.ValidateAPIKey)
			r.Post("/validate-token", authHandler.ValidateToken)
		})

		// WebAuthnエンドポイント
		webAuthnHandler.RegisterRoutes(r)

		// OAuth2エンドポイント
		r.Route("/oauth2", func(r chi.Router) {
			r.Get("/authorize", oauth2Handler.Authorize)
			r.Post("/authorize", oauth2Handler.Authorize)
			r.Post("/token", oauth2Handler.Token)
			r.Post("/revoke", oauth2Handler.Revoke)
			r.Post("/introspect", oauth2Handler.Introspect)

			// Client management
			r.Post("/clients", oauth2Handler.CreateClient)
			r.Get("/clients", oauth2Handler.GetClients)
			r.Get("/clients/*", oauth2Handler.GetClient)
			r.Delete("/clients/*", oauth2Handler.DeleteClient)
		})
	})

	// ヘルスチェック
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("auth OK"))
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Auth service (with WebAuthn) starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func connectDB() (*sql.DB, error) {
	// 環境変数からデータベース接続情報を取得
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// 個別の環境変数から構築
		host := os.Getenv("DB_HOST")
		if host == "" {
			host = "localhost"
		}
		port := os.Getenv("DB_PORT")
		if port == "" {
			port = "5432"
		}
		user := os.Getenv("DB_USER")
		if user == "" {
			user = "glen_dev"
		}
		password := os.Getenv("DB_PASSWORD")
		if password == "" {
			password = "glen_dev_pass"
		}
		dbname := os.Getenv("DB_NAME")
		if dbname == "" {
			dbname = "glen_dev"
		}

		dbURL = "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname + "?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}

	// 接続テスト
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func getRedisAddr() string {
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		return addr
	}
	return "localhost:6379"
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
