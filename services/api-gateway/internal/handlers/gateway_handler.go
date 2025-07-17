package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/dqx0/glen/api-gateway/internal/service"
)

// GatewayHandler はAPI Gatewayのメインハンドラー
type GatewayHandler struct {
	serviceProxy *service.ServiceProxy
}

// NewGatewayHandler は新しいGatewayHandlerを作成する
func NewGatewayHandler(serviceProxy *service.ServiceProxy) *GatewayHandler {
	return &GatewayHandler{
		serviceProxy: serviceProxy,
	}
}

// ProxyToUserService はユーザーサービスにリクエストをプロキシする
func (gh *GatewayHandler) ProxyToUserService(w http.ResponseWriter, r *http.Request) {
	log.Printf("[PROXY] Proxying %s %s to user-service", r.Method, r.URL.Path)
	gh.proxyToService(w, r, gh.serviceProxy.GetUserServiceURL(), "user-service")
}

// ProxyToAuthService は認証サービスにリクエストをプロキシする
func (gh *GatewayHandler) ProxyToAuthService(w http.ResponseWriter, r *http.Request) {
	gh.proxyToService(w, r, gh.serviceProxy.GetAuthServiceURL(), "auth-service")
}

// ProxyToSocialService はソーシャルサービスにリクエストをプロキシする
func (gh *GatewayHandler) ProxyToSocialService(w http.ResponseWriter, r *http.Request) {
	gh.proxyToService(w, r, gh.serviceProxy.GetSocialServiceURL(), "social-service")
}

// proxyToService は指定されたサービスにリクエストをプロキシする
func (gh *GatewayHandler) proxyToService(w http.ResponseWriter, r *http.Request, targetURL, serviceName string) {
	log.Printf("[PROXY] Sending request to %s: %s %s", serviceName, r.Method, r.URL.Path)
	
	// プロキシリクエストの送信
	resp, err := gh.serviceProxy.ProxyRequest(targetURL, r)
	if err != nil {
		log.Printf("[PROXY ERROR] Service %s unreachable: %v", serviceName, err)
		writeErrorResponse(w, http.StatusBadGateway, "Service temporarily unavailable")
		return
	}
	defer resp.Body.Close()
	
	log.Printf("[PROXY] Response from %s: status=%d", serviceName, resp.StatusCode)
	
	// レスポンスのコピー
	if err := gh.serviceProxy.CopyResponse(w, resp); err != nil {
		log.Printf("[PROXY ERROR] Failed to copy response from %s: %v", serviceName, err)
		return
	}
	
	// プロキシ完了のログ（エラーの場合のみ詳細ログ）
	if resp.StatusCode >= 400 {
		log.Printf("[PROXY ERROR] %s returned error status %d for %s %s", 
			serviceName, resp.StatusCode, r.Method, r.URL.Path)
	} else {
		log.Printf("[PROXY SUCCESS] %s processed %s %s successfully", 
			serviceName, r.Method, r.URL.Path)
	}
}

// HealthCheck はAPI Gatewayのヘルスチェックを行う
func (gh *GatewayHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	
	// 各サービスのヘルスチェック（簡易版）
	services := map[string]string{
		"user-service":   gh.serviceProxy.GetUserServiceURL(),
		"auth-service":   gh.serviceProxy.GetAuthServiceURL(),
		"social-service": gh.serviceProxy.GetSocialServiceURL(),
	}
	
	healthStatus := make(map[string]interface{})
	allHealthy := true
	
	for serviceName, serviceURL := range services {
		healthy := gh.checkServiceHealth(serviceURL)
		healthStatus[serviceName] = map[string]interface{}{
			"healthy": healthy,
			"url":     serviceURL,
		}
		if !healthy {
			allHealthy = false
		}
	}
	
	statusCode := http.StatusOK
	if !allHealthy {
		statusCode = http.StatusServiceUnavailable
	}
	
	response := map[string]interface{}{
		"healthy":  allHealthy,
		"services": healthStatus,
	}
	
	writeJSONResponse(w, statusCode, response)
}

// checkServiceHealth は個別サービスのヘルスチェックを行う
func (gh *GatewayHandler) checkServiceHealth(serviceURL string) bool {
	healthURL := serviceURL + "/health"
	
	req, err := http.NewRequest("GET", healthURL, nil)
	if err != nil {
		return false
	}
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

// APIInfo はAPI情報を返す
func (gh *GatewayHandler) APIInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	
	info := map[string]interface{}{
		"name":    "Glen API Gateway",
		"version": "1.0.0",
		"services": map[string]interface{}{
			"user-service":   gh.serviceProxy.GetUserServiceURL(),
			"auth-service":   gh.serviceProxy.GetAuthServiceURL(),
			"social-service": gh.serviceProxy.GetSocialServiceURL(),
		},
		"endpoints": []map[string]interface{}{
			{
				"path":        "/api/v1/users/register",
				"method":      "POST",
				"description": "User registration",
				"auth":        false,
			},
			{
				"path":        "/api/v1/users/login",
				"method":      "POST", 
				"description": "User login",
				"auth":        false,
			},
			{
				"path":        "/api/v1/users",
				"method":      "GET",
				"description": "Get user information",
				"auth":        true,
			},
			{
				"path":        "/api/v1/auth/login",
				"method":      "POST",
				"description": "Authentication and token generation",
				"auth":        false,
			},
			{
				"path":        "/api/v1/auth/refresh",
				"method":      "POST",
				"description": "Token refresh",
				"auth":        false,
			},
			{
				"path":        "/api/v1/auth/api-keys",
				"method":      "POST",
				"description": "API key creation",
				"auth":        true,
			},
			{
				"path":        "/api/v1/social/authorize",
				"method":      "POST",
				"description": "OAuth2 authorization URL",
				"auth":        false,
			},
			{
				"path":        "/api/v1/social/callback",
				"method":      "POST",
				"description": "OAuth2 callback handling",
				"auth":        false,
			},
		},
	}
	
	writeJSONResponse(w, http.StatusOK, info)
}

// writeJSONResponse はJSONレスポンスを書き込む
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	// 簡易的なJSON出力（実際のアプリケーションでは適切なJSONライブラリを使用）
	response := `{"status":"ok"}`
	if statusCode >= 400 {
		response = `{"status":"error"}`
	}
	
	if _, err := w.Write([]byte(response)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// writeErrorResponse はエラーレスポンスを書き込む
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	// 簡易的なエラーレスポンス
	response := `{"success":false,"error":"` + message + `"}`
	if _, err := w.Write([]byte(response)); err != nil {
		log.Printf("Failed to write error response: %v", err)
	}
	
	// エラーレスポンスのログ
	log.Printf("[ERROR RESPONSE] Sent %d: %s", statusCode, message)
}

// extractBearerToken はAuthorizationヘッダーからBearerトークンを抽出する
func extractBearerToken(authHeader string) string {
	const bearerPrefix = "Bearer "
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return authHeader[len(bearerPrefix):]
	}
	return ""
}