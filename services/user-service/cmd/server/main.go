package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	
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

	// Chi ルーターの設定
	r := chi.NewRouter()

	// ミドルウェア
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// CORS設定 - API Gateway経由でアクセスされるため無効化
	// API Gatewayで統一的にCORS処理を行う

	// API v1 ルートの設定
	r.Route("/api/v1", func(r chi.Router) {
		// 従来のユーザー関連のエンドポイント
		r.Post("/users/register", userHandler.Register)
		r.Post("/users/login", userHandler.Login)
		r.Get("/users", userHandler.GetUser)
		r.Get("/users/{user_id}", userHandler.GetUserByID)
		r.Get("/users/email/{email}", userHandler.GetUserByEmail)
		r.Get("/users/me", userHandler.GetMe)
		
	})

	// ヘルスチェック
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user OK"))
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("User service starting on port %s", port)
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
