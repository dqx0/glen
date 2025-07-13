package middleware

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// LoggingMiddleware はリクエストとレスポンスのログを記録するミドルウェア
type LoggingMiddleware struct{}

// NewLoggingMiddleware は新しいLoggingMiddlewareを作成する
func NewLoggingMiddleware() *LoggingMiddleware {
	return &LoggingMiddleware{}
}

// ResponseWriter はレスポンスステータスコードとボディをキャプチャするためのラッパー
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
	body       *bytes.Buffer
}

// NewResponseWriter は新しいResponseWriterを作成する
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

// WriteHeader はレスポンスヘッダーを書き込み、ステータスコードを記録する
func (rw *ResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write はレスポンスボディを書き込み、サイズを記録する
func (rw *ResponseWriter) Write(data []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(data)
	rw.size += size

	// エラーレスポンスの場合のみボディを記録
	if rw.statusCode >= 400 {
		rw.body.Write(data)
	}

	return size, err
}

// Handle はリクエストログを記録するミドルウェア
func (lm *LoggingMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// リクエストの詳細情報を収集
		requestInfo := lm.collectRequestInfo(r)

		// リクエストログ
		lm.logRequest(requestInfo)

		// レスポンスライターのラップ
		rw := NewResponseWriter(w)

		// パニック回復
		defer func() {
			if err := recover(); err != nil {
				lm.logPanic(requestInfo, err)
				http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		// 次のハンドラーの実行
		next(rw, r)

		// レスポンス情報を収集
		responseInfo := lm.collectResponseInfo(rw, time.Since(start))

		// レスポンスログ
		lm.logResponse(requestInfo, responseInfo)

		// エラーレスポンスの場合は詳細ログ
		if rw.statusCode >= 400 {
			lm.logError(requestInfo, responseInfo)
		}
	}
}

// RequestInfo はリクエストの詳細情報を保持する
type RequestInfo struct {
	Method      string
	URL         string
	Path        string
	Query       string
	RemoteAddr  string
	UserAgent   string
	ContentType string
	HasAuth     bool
	AuthType    string
	Headers     map[string]string
}

// ResponseInfo はレスポンスの詳細情報を保持する
type ResponseInfo struct {
	StatusCode int
	Size       int
	Duration   time.Duration
	Body       string
}

// collectRequestInfo はリクエストの詳細情報を収集する
func (lm *LoggingMiddleware) collectRequestInfo(r *http.Request) *RequestInfo {
	info := &RequestInfo{
		Method:      r.Method,
		URL:         r.URL.String(),
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		RemoteAddr:  r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		ContentType: r.Header.Get("Content-Type"),
		Headers:     make(map[string]string),
	}

	// 認証情報の確認
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		info.HasAuth = true
		if strings.HasPrefix(authHeader, "Bearer ") {
			info.AuthType = "Bearer"
		} else if strings.HasPrefix(authHeader, "ApiKey ") {
			info.AuthType = "ApiKey"
		} else {
			info.AuthType = "Other"
		}
	}

	// 重要なヘッダーを記録
	importantHeaders := []string{"X-User-ID", "X-Request-ID", "X-Forwarded-For", "Origin", "Referer"}
	for _, header := range importantHeaders {
		if value := r.Header.Get(header); value != "" {
			info.Headers[header] = value
		}
	}

	return info
}

// collectResponseInfo はレスポンスの詳細情報を収集する
func (lm *LoggingMiddleware) collectResponseInfo(rw *ResponseWriter, duration time.Duration) *ResponseInfo {
	info := &ResponseInfo{
		StatusCode: rw.statusCode,
		Size:       rw.size,
		Duration:   duration,
	}

	// エラーレスポンスのボディを記録
	if rw.statusCode >= 400 && rw.body.Len() > 0 {
		body := rw.body.String()
		// 長すぎる場合は切り詰める
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		info.Body = body
	}

	return info
}

// logRequest はリクエストログを出力する
func (lm *LoggingMiddleware) logRequest(info *RequestInfo) {
	var logParts []string

	// 基本情報
	logParts = append(logParts, fmt.Sprintf("[REQUEST] %s %s", info.Method, info.Path))

	// リモートアドレス
	if info.RemoteAddr != "" {
		logParts = append(logParts, fmt.Sprintf("from %s", info.RemoteAddr))
	}

	// クエリパラメータ
	if info.Query != "" {
		logParts = append(logParts, fmt.Sprintf("query: %s", info.Query))
	}

	// 認証情報
	if info.HasAuth {
		logParts = append(logParts, fmt.Sprintf("auth: %s", info.AuthType))
	}

	// ユーザーエージェント
	if info.UserAgent != "" {
		logParts = append(logParts, fmt.Sprintf("ua: %s", truncateString(info.UserAgent, 100)))
	}

	log.Printf("%s", strings.Join(logParts, " | "))
}

// logResponse はレスポンスログを出力する
func (lm *LoggingMiddleware) logResponse(reqInfo *RequestInfo, respInfo *ResponseInfo) {
	log.Printf("[RESPONSE] %s %s -> %d (%d bytes) in %v",
		reqInfo.Method, reqInfo.Path, respInfo.StatusCode, respInfo.Size, respInfo.Duration)
}

// logError はエラーログを出力する
func (lm *LoggingMiddleware) logError(reqInfo *RequestInfo, respInfo *ResponseInfo) {
	var logParts []string

	// エラー種別の判定
	errorType := "ERROR"
	if respInfo.StatusCode >= 500 {
		errorType = "CRITICAL"
	} else if respInfo.StatusCode == 401 || respInfo.StatusCode == 403 {
		errorType = "AUTH_ERROR"
	} else if respInfo.StatusCode == 404 {
		errorType = "NOT_FOUND"
	}

	logParts = append(logParts, fmt.Sprintf("[%s] %s %s -> %d",
		errorType, reqInfo.Method, reqInfo.Path, respInfo.StatusCode))

	// 追加情報
	logParts = append(logParts, fmt.Sprintf("duration: %v", respInfo.Duration))
	logParts = append(logParts, fmt.Sprintf("size: %d", respInfo.Size))
	logParts = append(logParts, fmt.Sprintf("remote: %s", reqInfo.RemoteAddr))

	// 認証情報
	if reqInfo.HasAuth {
		logParts = append(logParts, fmt.Sprintf("auth: %s", reqInfo.AuthType))
	}

	// ヘッダー情報
	if len(reqInfo.Headers) > 0 {
		headerParts := make([]string, 0, len(reqInfo.Headers))
		for k, v := range reqInfo.Headers {
			headerParts = append(headerParts, fmt.Sprintf("%s=%s", k, v))
		}
		logParts = append(logParts, fmt.Sprintf("headers: {%s}", strings.Join(headerParts, ", ")))
	}

	log.Printf("%s", strings.Join(logParts, " | "))

	// レスポンスボディ
	if respInfo.Body != "" {
		log.Printf("[ERROR_BODY] %s", respInfo.Body)
	}
}

// logPanic はパニックログを出力する
func (lm *LoggingMiddleware) logPanic(reqInfo *RequestInfo, err interface{}) {
	// スタックトレースを取得
	stack := make([]byte, 4096)
	length := runtime.Stack(stack, false)

	log.Printf("[PANIC] %s %s | Error: %v", reqInfo.Method, reqInfo.Path, err)
	log.Printf("[PANIC] Remote: %s | UA: %s", reqInfo.RemoteAddr, truncateString(reqInfo.UserAgent, 100))
	log.Printf("[PANIC] Stack trace:\n%s", string(stack[:length]))
}

// truncateString は文字列を指定された長さで切り詰める
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
