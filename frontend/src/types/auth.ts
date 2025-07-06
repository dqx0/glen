// 認証関連の型定義

export interface LoginRequest {
  user_id: string;
  username: string;
  session_name: string;
  scopes: string[];
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  scopes: string[];
}

export interface RefreshTokenRequest {
  refresh_token: string;
  username: string;
}

export interface RefreshResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

export interface CreateAPIKeyRequest {
  user_id: string;
  name: string;
  scopes: string[];
}

export interface APIKeyResponse {
  api_key: string;
  name: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
}

export interface RevokeTokenRequest {
  token_id: string;
  user_id: string;
}

export interface Token {
  id: string;
  user_id: string;
  token_type: 'session' | 'api_key';
  name: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
}

export interface ErrorResponse {
  error: string;
  message?: string;
}

export interface ValidateAPIKeyResponse {
  valid: boolean;
  user_id: string;
  scopes: string[];
  name: string;
}
