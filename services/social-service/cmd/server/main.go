package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dqx0/glen/social-service/internal/handlers"
	"github.com/dqx0/glen/social-service/internal/models"
	"github.com/dqx0/glen/social-service/internal/repository"
	_ "github.com/lib/pq"
)

func main() {
	// データベース接続
	db, err := connectDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// OAuth2設定の読み込み
	oauth2Configs := loadOAuth2Configs()

	// User serviceのURLを取得
	userServiceURL := os.Getenv("USER_SERVICE_URL")
	if userServiceURL == "" {
		userServiceURL = "http://localhost:8081" // デフォルトのuser-service URL
	}

	// 依存関係の構築
	socialRepo := repository.NewSocialAccountRepository(db)
	socialHandler := handlers.NewSocialHandler(socialRepo, oauth2Configs, userServiceURL)

	// ルーターの設定
	mux := http.NewServeMux()

	// ソーシャルログインエンドポイント
	mux.HandleFunc("/api/v1/social/authorize", socialHandler.GetAuthURL)
	mux.HandleFunc("/api/v1/social/login", socialHandler.HandleSocialLogin)
	mux.HandleFunc("/api/v1/social/callback", socialHandler.HandleCallback)
	mux.HandleFunc("/api/v1/social/accounts", socialHandler.GetUserSocialAccounts)
	mux.HandleFunc("/api/v1/social/accounts/", socialHandler.DeleteSocialAccount)
	mux.HandleFunc("/api/v1/social/providers", socialHandler.GetSupportedProviders)

	// ヘルスチェック
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("social OK"))
	})

	// デバッグ用：test-user-idのソーシャルアカウントを削除
	mux.HandleFunc("/debug/clear-test-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := socialRepo.DeleteByUserID(r.Context(), "test-user-id")
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test-user-id social accounts deleted"))
	})

	// デバッグ用：GoogleプロバイダーIDのソーシャルアカウントを削除
	mux.HandleFunc("/debug/clear-google-account", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 実際のGoogleプロバイダーIDで削除
		account, err := socialRepo.GetByProviderAndProviderID(r.Context(), "google", "102745493108574627406")
		if err != nil {
			http.Error(w, fmt.Sprintf("Account not found: %v", err), http.StatusNotFound)
			return
		}

		err = socialRepo.Delete(r.Context(), account.ID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Google social account deleted"))
	})

	// サーバー起動
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	log.Printf("Social service starting on port %s", port)
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
		dbname := os.Getenv("DB_NAME")
		if dbname == "" {
			dbname = "glen_dev"
		}

		sslmode := os.Getenv("DB_SSLMODE")
		if sslmode == "" {
			sslmode = "disable"
		}

		dbURL = "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname + "?sslmode=" + sslmode
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

func loadOAuth2Configs() map[string]*models.OAuth2Config {
	configs := make(map[string]*models.OAuth2Config)

	// Google OAuth2設定
	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		config := models.GetDefaultOAuth2Config(models.ProviderGoogle)
		config.ClientID = clientID
		config.ClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
		config.RedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")
		if config.RedirectURL == "" {
			config.RedirectURL = "http://localhost:8080/auth/google/callback"
		}
		configs[models.ProviderGoogle] = config
	}

	// GitHub OAuth2設定
	if clientID := os.Getenv("_GITHUB_CLIENT_ID"); clientID != "" {
		config := models.GetDefaultOAuth2Config(models.ProviderGitHub)
		config.ClientID = clientID
		config.ClientSecret = os.Getenv("_GITHUB_CLIENT_SECRET")
		config.RedirectURL = os.Getenv("GITHUB_REDIRECT_URL")
		if config.RedirectURL == "" {
			config.RedirectURL = "http://localhost:8080/auth/github/callback"
		}
		configs[models.ProviderGitHub] = config
	}

	// Discord OAuth2設定
	if clientID := os.Getenv("DISCORD_CLIENT_ID"); clientID != "" {
		config := models.GetDefaultOAuth2Config(models.ProviderDiscord)
		config.ClientID = clientID
		config.ClientSecret = os.Getenv("DISCORD_CLIENT_SECRET")
		config.RedirectURL = os.Getenv("DISCORD_REDIRECT_URL")
		if config.RedirectURL == "" {
			config.RedirectURL = "http://localhost:8080/auth/discord/callback"
		}
		configs[models.ProviderDiscord] = config
	}

	// 少なくとも1つのプロバイダーが設定されていることを確認
	if len(configs) == 0 {
		log.Println("Warning: No OAuth2 providers configured")

		// 開発環境用のダミー設定
		config := models.GetDefaultOAuth2Config(models.ProviderGoogle)
		config.ClientID = "dummy-client-id"
		config.ClientSecret = "dummy-client-secret"
		config.RedirectURL = "http://localhost:8080/auth/google/callback"
		configs[models.ProviderGoogle] = config
	}

	return configs
}
