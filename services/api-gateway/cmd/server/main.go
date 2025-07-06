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
	authMiddleware := middleware.NewAuthMiddleware(config.AuthService)

	// ルーターの設定
	mux := http.NewServeMux()

	// 認証が不要なエンドポイント
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("gateway OK"))
	})

	// ユーザー関連（認証不要 - 登録・ログイン）
	mux.HandleFunc("/api/v1/users/register", gatewayHandler.ProxyToUserService)
	mux.HandleFunc("/api/v1/users/login", gatewayHandler.ProxyToUserService)

	// 認証関連（認証不要 - トークン発行・リフレッシュ）
	mux.HandleFunc("/api/v1/auth/login", gatewayHandler.ProxyToAuthService)
	mux.HandleFunc("/api/v1/auth/refresh", gatewayHandler.ProxyToAuthService)

	// ソーシャルログイン（認証不要 - OAuth2フロー）
	mux.HandleFunc("/api/v1/social/authorize", gatewayHandler.ProxyToSocialService)
	mux.HandleFunc("/api/v1/social/callback", gatewayHandler.ProxyToSocialService)
	mux.HandleFunc("/api/v1/social/providers", gatewayHandler.ProxyToSocialService)

	// 認証が必要なエンドポイント
	// ユーザー情報取得
	mux.HandleFunc("/api/v1/users", authMiddleware.Handle(gatewayHandler.ProxyToUserService))

	// トークン管理
	mux.HandleFunc("/api/v1/auth/api-keys", authMiddleware.Handle(gatewayHandler.ProxyToAuthService))
	mux.HandleFunc("/api/v1/auth/tokens", authMiddleware.Handle(gatewayHandler.ProxyToAuthService))
	mux.HandleFunc("/api/v1/auth/revoke", authMiddleware.Handle(gatewayHandler.ProxyToAuthService))
	mux.HandleFunc("/api/v1/auth/validate-api-key", authMiddleware.Handle(gatewayHandler.ProxyToAuthService))

	// ソーシャルアカウント管理
	mux.HandleFunc("/api/v1/social/accounts", authMiddleware.Handle(gatewayHandler.ProxyToSocialService))

	// 全てのパスにワイルドカードハンドラーを追加してCORSを処理
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 全てのリクエストにCORSヘッダーを設定
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// OPTIONSリクエストの場合はここで終了
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// その他のリクエストは404を返す（具体的なルートがない場合）
		http.NotFound(w, r)
	})

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
