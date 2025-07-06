package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/dqx0/glen/user-service/internal/handlers"
	"github.com/dqx0/glen/user-service/internal/repository"
	"github.com/dqx0/glen/user-service/internal/service"
	_ "github.com/lib/pq" // PostgreSQL driver
)

func main() {
	// データベース接続
	db, err := connectDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// 依存関係の初期化
	userRepo := repository.NewUserRepository(db)
	userService := service.NewUserService(userRepo)
	userHandler := handlers.NewUserHandler(userService)

	// ルーターの設定
	mux := http.NewServeMux()

	// ユーザー関連のエンドポイント
	mux.HandleFunc("POST /api/v1/users/register", userHandler.Register)
	mux.HandleFunc("POST /api/v1/users/login", userHandler.Login)
	mux.HandleFunc("GET /api/v1/users", userHandler.GetUser)

	// ヘルスチェック
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user OK"))
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("User service starting on port %s", port)
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
