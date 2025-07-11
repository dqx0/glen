package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// Base64CredentialCreationOptions converts binary data to base64 for JSON response
type Base64CredentialCreationOptions struct {
	Challenge              string                               `json:"challenge"`
	RP                     *models.RelyingPartyEntity          `json:"rp"`
	User                   *Base64UserEntity                   `json:"user"`
	PubKeyCredParams       []models.PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                *int                                `json:"timeout,omitempty"`
	ExcludeCredentials     []Base64CredentialDescriptor        `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *models.AuthenticatorSelectionCriteria `json:"authenticatorSelection,omitempty"`
	Attestation            models.AttestationConveyancePreference `json:"attestation,omitempty"`
}

// Base64UserEntity represents user entity with base64-encoded ID
type Base64UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// Base64CredentialDescriptor represents credential descriptor with base64-encoded ID
type Base64CredentialDescriptor struct {
	Type       string                            `json:"type"`
	ID         string                            `json:"id"`
	Transports []models.AuthenticatorTransport  `json:"transports,omitempty"`
}

// Base64CredentialRequestOptions converts binary data to base64 for JSON response
type Base64CredentialRequestOptions struct {
	Challenge        string                               `json:"challenge"`
	Timeout          *int                                `json:"timeout,omitempty"`
	RPID             string                              `json:"rpId"`
	AllowCredentials []Base64CredentialDescriptor        `json:"allowCredentials,omitempty"`
	UserVerification models.UserVerificationRequirement `json:"userVerification,omitempty"`
}

// convertCreationOptionsToBase64 converts models.PublicKeyCredentialCreationOptions to Base64 format
func convertCreationOptionsToBase64(options *models.PublicKeyCredentialCreationOptions) *Base64CredentialCreationOptions {
	if options == nil {
		return nil
	}

	result := &Base64CredentialCreationOptions{
		Challenge:              base64.URLEncoding.EncodeToString(options.Challenge),
		RP:                     options.RP,
		PubKeyCredParams:       options.PubKeyCredParams,
		Timeout:                options.Timeout,
		AuthenticatorSelection: options.AuthenticatorSelection,
		Attestation:            options.Attestation,
	}

	// Convert user entity
	if options.User != nil {
		result.User = &Base64UserEntity{
			ID:          base64.URLEncoding.EncodeToString(options.User.ID),
			Name:        options.User.Name,
			DisplayName: options.User.DisplayName,
		}
	}

	// Convert exclude credentials
	if len(options.ExcludeCredentials) > 0 {
		result.ExcludeCredentials = make([]Base64CredentialDescriptor, len(options.ExcludeCredentials))
		for i, cred := range options.ExcludeCredentials {
			result.ExcludeCredentials[i] = Base64CredentialDescriptor{
				Type:       cred.Type,
				ID:         base64.URLEncoding.EncodeToString(cred.ID),
				Transports: cred.Transports,
			}
		}
	}

	return result
}

// convertRequestOptionsToBase64 converts models.PublicKeyCredentialRequestOptions to Base64 format
func convertRequestOptionsToBase64(options *models.PublicKeyCredentialRequestOptions) *Base64CredentialRequestOptions {
	if options == nil {
		return nil
	}

	result := &Base64CredentialRequestOptions{
		Challenge:        base64.URLEncoding.EncodeToString(options.Challenge),
		Timeout:          options.Timeout,
		RPID:             options.RPID,
		UserVerification: options.UserVerification,
	}

	// Convert allow credentials
	if len(options.AllowCredentials) > 0 {
		result.AllowCredentials = make([]Base64CredentialDescriptor, len(options.AllowCredentials))
		for i, cred := range options.AllowCredentials {
			result.AllowCredentials[i] = Base64CredentialDescriptor{
				Type:       cred.Type,
				ID:         base64.URLEncoding.EncodeToString(cred.ID),
				Transports: cred.Transports,
			}
		}
	}

	return result
}

// parseAttestationResponse parses and validates attestation response from client
func parseAttestationResponse(data map[string]interface{}) (*models.AuthenticatorAttestationResponse, error) {
	response := &models.AuthenticatorAttestationResponse{}

	// Parse ID
	if id, ok := data["id"].(string); ok {
		response.ID = id
	} else {
		return nil, fmt.Errorf("missing or invalid id")
	}

	// Parse RawID
	if rawID, ok := data["rawId"].(string); ok {
		decoded, err := base64.URLEncoding.DecodeString(rawID)
		if err != nil {
			return nil, fmt.Errorf("invalid rawId base64: %w", err)
		}
		response.RawID = decoded
	} else {
		return nil, fmt.Errorf("missing or invalid rawId")
	}

	// Parse Type
	if typ, ok := data["type"].(string); ok {
		response.Type = typ
	} else {
		return nil, fmt.Errorf("missing or invalid type")
	}

	// Parse Response
	if respData, ok := data["response"].(map[string]interface{}); ok {
		response.Response = &models.AuthenticatorAttestationResponseData{}

		// Parse ClientDataJSON
		if clientDataJSON, ok := respData["clientDataJSON"].(string); ok {
			decoded, err := base64.URLEncoding.DecodeString(clientDataJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid clientDataJSON base64: %w", err)
			}
			response.Response.ClientDataJSON = decoded
		} else {
			return nil, fmt.Errorf("missing or invalid clientDataJSON")
		}

		// Parse AttestationObject
		if attestationObject, ok := respData["attestationObject"].(string); ok {
			decoded, err := base64.URLEncoding.DecodeString(attestationObject)
			if err != nil {
				return nil, fmt.Errorf("invalid attestationObject base64: %w", err)
			}
			response.Response.AttestationObject = decoded
		} else {
			return nil, fmt.Errorf("missing or invalid attestationObject")
		}

		// Parse Transports (optional)
		if transports, ok := respData["transports"].([]interface{}); ok {
			response.Response.Transports = make([]string, len(transports))
			for i, transport := range transports {
				if t, ok := transport.(string); ok {
					response.Response.Transports[i] = t
				}
			}
		}
	} else {
		return nil, fmt.Errorf("missing or invalid response")
	}

	return response, nil
}

// parseAssertionResponse parses and validates assertion response from client
func parseAssertionResponse(data map[string]interface{}) (*models.AuthenticatorAssertionResponse, error) {
	response := &models.AuthenticatorAssertionResponse{}

	// Parse ID
	if id, ok := data["id"].(string); ok {
		response.ID = id
	} else {
		return nil, fmt.Errorf("missing or invalid id")
	}

	// Parse RawID
	if rawID, ok := data["rawId"].(string); ok {
		decoded, err := base64.URLEncoding.DecodeString(rawID)
		if err != nil {
			return nil, fmt.Errorf("invalid rawId base64: %w", err)
		}
		response.RawID = decoded
	} else {
		return nil, fmt.Errorf("missing or invalid rawId")
	}

	// Parse Type
	if typ, ok := data["type"].(string); ok {
		response.Type = typ
	} else {
		return nil, fmt.Errorf("missing or invalid type")
	}

	// Parse Response
	if respData, ok := data["response"].(map[string]interface{}); ok {
		response.Response = &models.AuthenticatorAssertionResponseData{}

		// Parse ClientDataJSON
		if clientDataJSON, ok := respData["clientDataJSON"].(string); ok {
			decoded, err := base64.URLEncoding.DecodeString(clientDataJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid clientDataJSON base64: %w", err)
			}
			response.Response.ClientDataJSON = decoded
		} else {
			return nil, fmt.Errorf("missing or invalid clientDataJSON")
		}

		// Parse AuthenticatorData
		if authenticatorData, ok := respData["authenticatorData"].(string); ok {
			decoded, err := base64.URLEncoding.DecodeString(authenticatorData)
			if err != nil {
				return nil, fmt.Errorf("invalid authenticatorData base64: %w", err)
			}
			response.Response.AuthenticatorData = decoded
		} else {
			return nil, fmt.Errorf("missing or invalid authenticatorData")
		}

		// Parse Signature
		if signature, ok := respData["signature"].(string); ok {
			decoded, err := base64.URLEncoding.DecodeString(signature)
			if err != nil {
				return nil, fmt.Errorf("invalid signature base64: %w", err)
			}
			response.Response.Signature = decoded
		} else {
			return nil, fmt.Errorf("missing or invalid signature")
		}

		// Parse UserHandle (optional)
		if userHandle, ok := respData["userHandle"].(string); ok && userHandle != "" {
			decoded, err := base64.URLEncoding.DecodeString(userHandle)
			if err != nil {
				return nil, fmt.Errorf("invalid userHandle base64: %w", err)
			}
			response.Response.UserHandle = decoded
		}
	} else {
		return nil, fmt.Errorf("missing or invalid response")
	}

	return response, nil
}

// parseRegistrationFinishRequest parses registration finish request with proper base64 handling
func parseRegistrationFinishRequest(r *http.Request) (*service.RegistrationFinishRequest, error) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Parse session ID
	sessionID, ok := data["sessionId"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid sessionId")
	}

	// Parse attestation response
	responseData, ok := data["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid response")
	}

	attestationResponse, err := parseAttestationResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation response: %w", err)
	}

	// Parse client extensions (optional)
	var clientExtensions map[string]interface{}
	if extensions, ok := data["clientExtensions"].(map[string]interface{}); ok {
		clientExtensions = extensions
	}

	return &service.RegistrationFinishRequest{
		SessionID:         sessionID,
		AttestationResponse: attestationResponse,
		ClientExtensions:  clientExtensions,
	}, nil
}

// parseAuthenticationFinishRequest parses authentication finish request with proper base64 handling
func parseAuthenticationFinishRequest(r *http.Request) (*service.AuthenticationFinishRequest, error) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Parse session ID
	sessionID, ok := data["sessionId"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid sessionId")
	}

	// Parse assertion response
	responseData, ok := data["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid response")
	}

	assertionResponse, err := parseAssertionResponse(responseData)
	if err != nil {
		return nil, fmt.Errorf("invalid assertion response: %w", err)
	}

	// Parse client extensions (optional)
	var clientExtensions map[string]interface{}
	if extensions, ok := data["clientExtensions"].(map[string]interface{}); ok {
		clientExtensions = extensions
	}

	return &service.AuthenticationFinishRequest{
		SessionID:         sessionID,
		AssertionResponse: assertionResponse,
		ClientExtensions:  clientExtensions,
	}, nil
}

// validateOrigin validates the request origin against allowed origins
func validateOrigin(r *http.Request, allowedOrigins []string) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return fmt.Errorf("missing Origin header")
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return nil
		}
	}

	return fmt.Errorf("origin %s not allowed", origin)
}

// sanitizeUserInput sanitizes user input to prevent XSS and injection attacks
func sanitizeUserInput(input string) string {
	// Basic sanitization - remove dangerous characters
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")
	input = strings.ReplaceAll(input, "&", "&amp;")
	return input
}

// WebAuthnErrorResponse represents a WebAuthn-specific error response
type WebAuthnErrorResponse struct {
	Error     string `json:"error"`
	Details   string `json:"details,omitempty"`
	Code      int    `json:"code"`
	Type      string `json:"type,omitempty"`
	Timestamp string `json:"timestamp"`
}

// writeWebAuthnErrorResponse writes a WebAuthn-specific error response
func writeWebAuthnErrorResponse(w http.ResponseWriter, statusCode int, errorType, message, details string) {
	errorResponse := WebAuthnErrorResponse{
		Error:     message,
		Details:   details,
		Code:      statusCode,
		Type:      errorType,
		Timestamp: fmt.Sprintf("%d", time.Now().Unix()),
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		// Fallback to plain text error
		http.Error(w, message, statusCode)
	}
}

// handleWebAuthnServiceError handles service errors with WebAuthn-specific formatting
func handleWebAuthnServiceError(w http.ResponseWriter, err error) {
	if serviceErr, ok := err.(*service.ServiceError); ok {
		statusCode := serviceErr.HTTPStatusCode()
		writeWebAuthnErrorResponse(w, statusCode, string(serviceErr.Type), serviceErr.Message, serviceErr.Details)
		return
	}
	
	// Generic error handling
	writeWebAuthnErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err.Error())
}