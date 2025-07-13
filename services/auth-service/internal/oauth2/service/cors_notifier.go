package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

// CORSNotifier defines the interface for notifying CORS changes
type CORSNotifier interface {
	UpdateOrigins(ctx context.Context, origins []string, action string) error
}

// HTTPCORSNotifier implements CORSNotifier using HTTP requests to API Gateway
type HTTPCORSNotifier struct {
	gatewayURL string
	client     *http.Client
}

// NewHTTPCORSNotifier creates a new HTTP CORS notifier
func NewHTTPCORSNotifier(gatewayURL string) *HTTPCORSNotifier {
	return &HTTPCORSNotifier{
		gatewayURL: gatewayURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// UpdateOrigins sends a request to API Gateway to update CORS origins
func (n *HTTPCORSNotifier) UpdateOrigins(ctx context.Context, origins []string, action string) error {
	if len(origins) == 0 {
		log.Printf("CORS Notifier: No origins to %s", action)
		return nil
	}

	// Prepare request body
	reqBody := map[string]interface{}{
		"origins": origins,
		"action":  action,
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal CORS update request: %w", err)
	}
	
	// Create request
	endpoint := n.gatewayURL + "/internal/cors/origins"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create CORS update request: %w", err)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Service", "auth-service")
	
	log.Printf("CORS Notifier: Sending %s request for %d origins to %s", action, len(origins), endpoint)
	
	// Send request
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send CORS update request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CORS update failed with status %d", resp.StatusCode)
	}
	
	log.Printf("CORS Notifier: Successfully %s %d origins", action, len(origins))
	return nil
}

// extractOriginsFromRedirectURIs extracts unique origins from redirect URIs
func extractOriginsFromRedirectURIs(redirectURIs []string) []string {
	originSet := make(map[string]bool)
	
	for _, uri := range redirectURIs {
		if uri == "" {
			continue
		}
		
		u, err := url.Parse(uri)
		if err != nil {
			log.Printf("CORS Notifier: Invalid redirect URI: %s, error: %v", uri, err)
			continue
		}
		
		if u.Host == "" {
			log.Printf("CORS Notifier: Redirect URI missing host: %s", uri)
			continue
		}
		
		origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		originSet[origin] = true
	}
	
	// Convert set to slice
	origins := make([]string, 0, len(originSet))
	for origin := range originSet {
		origins = append(origins, origin)
	}
	
	return origins
}

// notifyCORSUpdate is a helper function to extract origins and notify CORS changes
func notifyCORSUpdate(ctx context.Context, notifier CORSNotifier, redirectURIs []string, action string) error {
	if notifier == nil {
		log.Printf("CORS Notifier: Notifier is nil, skipping %s operation", action)
		return nil
	}
	
	origins := extractOriginsFromRedirectURIs(redirectURIs)
	if len(origins) == 0 {
		log.Printf("CORS Notifier: No valid origins extracted from redirect URIs")
		return nil
	}
	
	return notifier.UpdateOrigins(ctx, origins, action)
}

// NullCORSNotifier is a no-op implementation for testing or when CORS notification is disabled
type NullCORSNotifier struct{}

// NewNullCORSNotifier creates a new null CORS notifier
func NewNullCORSNotifier() *NullCORSNotifier {
	return &NullCORSNotifier{}
}

// UpdateOrigins does nothing in the null implementation
func (n *NullCORSNotifier) UpdateOrigins(ctx context.Context, origins []string, action string) error {
	log.Printf("Null CORS Notifier: Would %s %d origins (no-op)", action, len(origins))
	return nil
}