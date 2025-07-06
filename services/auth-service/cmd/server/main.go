package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/dqx0/glen/auth-service/internal/handlers"
	"github.com/dqx0/glen/auth-service/internal/repository"
	"github.com/dqx0/glen/auth-service/internal/service"
	_ "github.com/lib/pq"
)

func main() {
	// データベース接続
	db, err := connectDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

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

	// ルーターの設定
	mux := http.NewServeMux()

	// 認証エンドポイント
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("/api/v1/auth/refresh", authHandler.RefreshToken)
	mux.HandleFunc("/api/v1/auth/api-keys", authHandler.CreateAPIKey)
	mux.HandleFunc("/api/v1/auth/revoke", authHandler.RevokeToken)
	mux.HandleFunc("/api/v1/auth/tokens", authHandler.ListTokens)
	mux.HandleFunc("/api/v1/auth/validate-api-key", authHandler.ValidateAPIKey)

	// ヘルスチェック
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("auth OK"))
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Auth service starting on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
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
