package middleware

import (
	"net/http"
)

// CORSMiddleware はCORS（Cross-Origin Resource Sharing）を処理するミドルウェア
type CORSMiddleware struct {
	allowedOrigins []string
	allowedMethods []string
	allowedHeaders []string
}

// NewCORSMiddleware は新しいCORSMiddlewareを作成する
func NewCORSMiddleware() *CORSMiddleware {
	return &CORSMiddleware{
		allowedOrigins: []string{"http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000", "http://127.0.0.1:8080"}, // フロントエンドのオリジンを明示的に許可
		allowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		allowedHeaders: []string{"Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin", "X-CSRF-Token", "Access-Control-Request-Method", "Access-Control-Request-Headers"},
	}
}

// Handle はCORSヘッダーを設定してからハンドラーを実行する
func (c *CORSMiddleware) Handle(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// リクエストのOriginを取得
		origin := r.Header.Get("Origin")

		// 開発環境用により寛容な設定
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", joinStrings(c.allowedMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", joinStrings(c.allowedHeaders, ", "))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24時間

		// OPTIONSリクエスト（プリフライト）の処理
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 次のハンドラーを実行
		handler(w, r)
	}
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
