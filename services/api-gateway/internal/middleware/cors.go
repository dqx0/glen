package middleware

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

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
	// TODO: 実装時にOAuth2クライアントのredirect_uriからオリジンを抽出して比較
	// 現在は安全のためfalseを返す
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
