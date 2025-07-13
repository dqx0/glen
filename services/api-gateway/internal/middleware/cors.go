package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

// CORSRepository defines the interface for CORS origin persistence
type CORSRepository interface {
	AddOrigin(ctx context.Context, origin, clientID string) error
	RemoveOrigin(ctx context.Context, origin string) error
	GetAllOrigins(ctx context.Context) ([]string, error)
	RemoveOriginsByClientID(ctx context.Context, clientID string) error
	GetOriginsByClientID(ctx context.Context, clientID string) ([]string, error)
}

// OriginStats represents statistics about CORS origins
type OriginStats struct {
	TotalOrigins     int            `json:"total_origins"`
	TotalClients     int            `json:"total_clients"`
	OriginsPerClient map[string]int `json:"origins_per_client"`
}

// CORSMiddleware はCORS（Cross-Origin Resource Sharing）を処理するミドルウェア
type CORSMiddleware struct {
	allowedOrigins     []string
	allowedMethods     []string
	allowedHeaders     []string
	allowedPatterns    []*regexp.Regexp
	allowCredentials   bool
	maxAge             string
	authServiceURL     string
	developmentMode    bool
	allowAnyLocalhost  bool
	dynamicOrigins     sync.Map // thread-safe map for dynamic origins
	mutex              sync.RWMutex
	repository         CORSRepository // for persistence
}

// NewCORSMiddleware は新しいCORSMiddlewareを作成する
func NewCORSMiddleware(authServiceURL string) *CORSMiddleware {
	env := os.Getenv("ENVIRONMENT")
	isDev := env == "development" || env == "dev" || env == ""

	cors := &CORSMiddleware{
		allowedMethods:    getEnvStringSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
		allowedHeaders:    getEnvStringSlice("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin", "X-CSRF-Token", "Access-Control-Request-Method", "Access-Control-Request-Headers", "X-User-ID"}),
		allowCredentials:  getEnvBool("CORS_ALLOW_CREDENTIALS", true),
		maxAge:            getEnvString("CORS_MAX_AGE", "86400"),
		authServiceURL:    authServiceURL,
		developmentMode:   isDev,
		allowAnyLocalhost: getEnvBool("CORS_ALLOW_ANY_LOCALHOST", isDev),
	}

	// 許可するオリジンの設定
	origins := getEnvStringSlice("CORS_ALLOWED_ORIGINS", getDefaultOrigins())
	cors.allowedOrigins = origins

	// パターンマッチング用の正規表現を準備（開発モードでのみ）
	if cors.developmentMode {
		cors.compileOriginPatterns()
	}

	log.Printf("CORS configured: dev=%v, localhost=%v, origins=%d, credentials=%v", 
		cors.developmentMode, cors.allowAnyLocalhost, len(cors.allowedOrigins), cors.allowCredentials)
	return cors
}

// NewCORSMiddlewareWithRepository は永続化機能付きのCORSMiddlewareを作成する
func NewCORSMiddlewareWithRepository(authServiceURL string, repository CORSRepository) *CORSMiddleware {
	cors := NewCORSMiddleware(authServiceURL)
	cors.repository = repository
	return cors
}

// getDefaultOrigins はデフォルトの許可オリジンを返す
func getDefaultOrigins() []string {
	env := os.Getenv("ENVIRONMENT")
	
	if env == "production" {
		// 本番環境では信頼できるオリジンのみ
		return []string{
			"https://glen.dqx0.com",
			"https://api.glen.dqx0.com",
		}
	}
	
	// 開発環境では基本的なオリジンのみ
	return []string{
		"http://localhost:5173",  // フロントエンド
		"http://localhost:3000",  // 代替フロントエンド
		"http://localhost:3001",  // サンプルアプリ
		"https://glen.dqx0.com",  // 本番フロントエンド
	}
}

// compileOriginPatterns は正規表現パターンをコンパイルする
func (c *CORSMiddleware) compileOriginPatterns() {
	for _, origin := range c.allowedOrigins {
		// パターンに正規表現文字が含まれている場合はコンパイル
		if strings.Contains(origin, "[") || strings.Contains(origin, "*") {
			if pattern, err := regexp.Compile("^" + origin + "$"); err == nil {
				c.allowedPatterns = append(c.allowedPatterns, pattern)
			} else {
				log.Printf("Invalid CORS origin pattern: %s, error: %v", origin, err)
			}
		}
	}
}

// Handle はCORSヘッダーを設定してからハンドラーを実行する
func (c *CORSMiddleware) Handle(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// リクエストのOriginを取得
		origin := r.Header.Get("Origin")

		// Originが設定されている場合のみチェック
		if origin != "" {
			if c.isOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				// 許可されていないオリジンの場合はログに記録
				log.Printf("CORS: Rejected origin: %s", origin)
			}
		}

		// 共通のCORSヘッダーを設定
		w.Header().Set("Access-Control-Allow-Methods", joinStrings(c.allowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", joinStrings(c.allowedHeaders, ", "))
		
		if c.allowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		
		w.Header().Set("Access-Control-Max-Age", c.maxAge)

		// OPTIONSリクエスト（プリフライト）の処理
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 次のハンドラーを実行
		handler(w, r)
	}
}

// isOriginAllowed は指定されたオリジンが許可されているかチェックする
func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	// 完全一致チェック
	for _, allowed := range c.allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	// 開発モードでのlocalhost許可
	if c.allowAnyLocalhost && c.isLocalhostOrigin(origin) {
		return true
	}

	// パターンマッチングチェック（開発モードのみ）
	if c.developmentMode {
		for _, pattern := range c.allowedPatterns {
			if pattern.MatchString(origin) {
				return true
			}
		}
	}

	// 動的オリジンチェック
	if _, exists := c.dynamicOrigins.Load(origin); exists {
		return true
	}

	// OAuth2クライアントのオリジンチェック（本番環境での動的許可）
	if !c.developmentMode {
		return c.isOAuth2ClientOrigin(origin)
	}

	return false
}

// isLocalhostOrigin はローカルホストのオリジンかチェックする
func (c *CORSMiddleware) isLocalhostOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://localhost:") || 
		   strings.HasPrefix(origin, "http://127.0.0.1:") ||
		   strings.HasPrefix(origin, "https://localhost:") || 
		   strings.HasPrefix(origin, "https://127.0.0.1:")
}

// isOAuth2ClientOrigin はOAuth2クライアントとして登録されたオリジンかチェックする
func (c *CORSMiddleware) isOAuth2ClientOrigin(origin string) bool {
	if c.authServiceURL == "" {
		return false
	}
	
	// OAuth2クライアントAPIを呼び出してオリジンを検証
	return c.verifyOriginWithAuthService(origin)
}

// verifyOriginWithAuthService はAuth ServiceのAPIを呼び出してオリジンを検証する
func (c *CORSMiddleware) verifyOriginWithAuthService(origin string) bool {
	// HTTP クライアントでAuth Serviceの /api/v1/oauth2/clients/verify-origin エンドポイントを呼び出し
	// 実装は必要時に追加
	return false
}

// joinStrings は文字列スライスを結合する
func joinStrings(slice []string, separator string) string {
	if len(slice) == 0 {
		return ""
	}

	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += separator + slice[i]
	}

	return result
}

// Environment variable helper functions

// getEnvString は環境変数を取得し、設定されていない場合はデフォルト値を返す
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool は環境変数をbooleanとして取得する
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

// getEnvStringSlice は環境変数をカンマ区切りで分割してスライスとして取得する
func getEnvStringSlice(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	
	// カンマ区切りで分割し、空白をトリム
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	if len(result) == 0 {
		return defaultValue
	}
	
	return result
}

// AddDynamicOrigins は動的にオリジンを許可リストに追加する
func (c *CORSMiddleware) AddDynamicOrigins(origins []string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, origin := range origins {
		if c.isValidOrigin(origin) {
			c.dynamicOrigins.Store(origin, true)
			log.Printf("CORS: Added dynamic origin: %s", origin)
		} else {
			log.Printf("CORS: Rejected invalid origin: %s", origin)
		}
	}
}

// RemoveDynamicOrigins は動的オリジンを許可リストから削除する
func (c *CORSMiddleware) RemoveDynamicOrigins(origins []string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, origin := range origins {
		c.dynamicOrigins.Delete(origin)
		log.Printf("CORS: Removed dynamic origin: %s", origin)
	}
}

// GetDynamicOrigins は現在の動的オリジン一覧を取得する（デバッグ用）
func (c *CORSMiddleware) GetDynamicOrigins() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var origins []string
	c.dynamicOrigins.Range(func(key, value interface{}) bool {
		if origin, ok := key.(string); ok {
			origins = append(origins, origin)
		}
		return true
	})
	
	return origins
}

// isValidOrigin はオリジンが有効かどうかをチェックする
func (c *CORSMiddleware) isValidOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	
	// 本番環境ではHTTPS必須（localhost除く）
	if !c.developmentMode && u.Scheme != "https" && !strings.Contains(u.Host, "localhost") && !strings.Contains(u.Host, "127.0.0.1") {
		return false
	}
	
	// ホスト名が存在することを確認
	if u.Host == "" {
		return false
	}
	
	return true
}

// LoadPersistedOrigins はデータベースから永続化されたオリジンを読み込む
func (c *CORSMiddleware) LoadPersistedOrigins(ctx context.Context) error {
	if c.repository == nil {
		log.Printf("CORS: No repository configured, skipping persistence load")
		return nil
	}

	origins, err := c.repository.GetAllOrigins(ctx)
	if err != nil {
		return fmt.Errorf("failed to load persisted CORS origins: %w", err)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, origin := range origins {
		c.dynamicOrigins.Store(origin, true)
	}

	log.Printf("CORS: Loaded %d persisted origins from database", len(origins))
	return nil
}

// AddDynamicOriginsWithPersistence は動的オリジンを追加し、データベースに永続化する
func (c *CORSMiddleware) AddDynamicOriginsWithPersistence(ctx context.Context, origins []string, clientID string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, origin := range origins {
		if c.isValidOrigin(origin) {
			// Add to memory cache
			c.dynamicOrigins.Store(origin, true)
			log.Printf("CORS: Added dynamic origin to memory: %s", origin)
			
			// Persist to database
			if c.repository != nil {
				if err := c.repository.AddOrigin(ctx, origin, clientID); err != nil {
					log.Printf("CORS: Failed to persist origin %s: %v", origin, err)
					// Continue operation even if persistence fails
				} else {
					log.Printf("CORS: Persisted dynamic origin: %s for client: %s", origin, clientID)
				}
			}
		} else {
			log.Printf("CORS: Rejected invalid origin: %s", origin)
		}
	}
}

// RemoveDynamicOriginsWithPersistence は動的オリジンを削除し、データベースからも削除する
func (c *CORSMiddleware) RemoveDynamicOriginsWithPersistence(ctx context.Context, origins []string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, origin := range origins {
		// Remove from memory cache
		c.dynamicOrigins.Delete(origin)
		log.Printf("CORS: Removed dynamic origin from memory: %s", origin)
		
		// Remove from database
		if c.repository != nil {
			if err := c.repository.RemoveOrigin(ctx, origin); err != nil {
				log.Printf("CORS: Failed to remove persisted origin %s: %v", origin, err)
				// Continue operation even if persistence fails
			} else {
				log.Printf("CORS: Removed persisted dynamic origin: %s", origin)
			}
		}
	}
}

// RemoveOriginsByClientIDWithPersistence はクライアントIDに関連するオリジンを削除する
func (c *CORSMiddleware) RemoveOriginsByClientIDWithPersistence(ctx context.Context, clientID string) error {
	if c.repository == nil {
		log.Printf("CORS: No repository configured, skipping client origin cleanup")
		return nil
	}

	// Get origins for this client before removing them
	origins, err := c.repository.GetOriginsByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf("failed to get origins for client %s: %w", clientID, err)
	}

	// Remove from database
	if err := c.repository.RemoveOriginsByClientID(ctx, clientID); err != nil {
		return fmt.Errorf("failed to remove origins for client %s: %w", clientID, err)
	}

	// Remove from memory cache
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, origin := range origins {
		c.dynamicOrigins.Delete(origin)
		log.Printf("CORS: Removed origin %s for deleted client %s", origin, clientID)
	}

	log.Printf("CORS: Cleaned up %d origins for client: %s", len(origins), clientID)
	return nil
}

// GetPersistedOriginStats は永続化されたオリジンの統計情報を取得する
func (c *CORSMiddleware) GetPersistedOriginStats(ctx context.Context) (map[string]interface{}, error) {
	if c.repository == nil {
		return map[string]interface{}{
			"persistence": "disabled",
		}, nil
	}

	// Get basic stats if the repository supports it
	if statsRepo, ok := c.repository.(interface {
		GetOriginStats(ctx context.Context) (*OriginStats, error)
	}); ok {
		stats, err := statsRepo.GetOriginStats(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get origin stats: %w", err)
		}
		
		return map[string]interface{}{
			"persistence":        "enabled",
			"total_origins":      stats.TotalOrigins,
			"total_clients":      stats.TotalClients,
			"origins_per_client": stats.OriginsPerClient,
		}, nil
	}

	// Fallback to basic count
	origins, err := c.repository.GetAllOrigins(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all origins: %w", err)
	}

	return map[string]interface{}{
		"persistence":   "enabled",
		"total_origins": len(origins),
	}, nil
}
