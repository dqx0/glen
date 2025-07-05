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
	// 環境変数からデータベース接続情報を取得
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://user:password@localhost/glen_dev?sslmode=disable"
	}

	// データベース接続
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// データベース接続確認
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

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
		w.Write([]byte("OK"))
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