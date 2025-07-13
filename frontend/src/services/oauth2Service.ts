interface OAuth2Client {
  id: string;
  client_id: string;
  client_secret?: string;
  name: string;
  description: string;
  redirect_uris: string[];
  scopes: string[];
  is_public: boolean;
  is_active: boolean;
  created_at: string;
}

interface CreateClientRequest {
  user_id: string;
  name: string;
  description: string;
  redirect_uris: string[];
  scopes: string[];
  is_public: boolean;
}

interface CreateClientResponse {
  id: string;
  client_id: string;
  client_secret?: string;
  name: string;
  description: string;
  redirect_uris: string[];
  scopes: string[];
  is_public: boolean;
  is_active: boolean;
  created_at: string;
}

interface AuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

interface TokenRequest {
  grant_type: string;
  code?: string;
  redirect_uri?: string;
  client_id: string;
  client_secret?: string;
  code_verifier?: string;
  refresh_token?: string;
  scope?: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

import { apiClient } from '../api/client';

export class OAuth2Service {
  private static baseUrl = '/api/v1/oauth2';

  // Client Management
  static async createClient(request: CreateClientRequest): Promise<CreateClientResponse> {
    try {
      const response = await apiClient.post(`${this.baseUrl}/clients`, request);
      return response.data;
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || 
                          error.response?.data?.message || 
                          error.message || 
                          'Failed to create client';
      throw new Error(errorMessage);
    }
  }

  static async getClients(userId: string): Promise<OAuth2Client[]> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/clients?user_id=${encodeURIComponent(userId)}`);
      return Array.isArray(response.data) ? response.data : [];
    } catch (error: any) {
      if (error.response?.status === 404) {
        return []; // No clients found
      }
      const errorMessage = error.response?.data?.error_description || 
                          error.response?.data?.message || 
                          error.message || 
                          'Failed to fetch clients';
      throw new Error(errorMessage);
    }
  }

  static async getClient(clientId: string): Promise<OAuth2Client> {
    try {
      const response = await apiClient.get(`${this.baseUrl}/clients/${encodeURIComponent(clientId)}`);
      return response.data;
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || 
                          error.response?.data?.message || 
                          error.message || 
                          'Failed to fetch client';
      throw new Error(errorMessage);
    }
  }

  static async deleteClient(clientId: string): Promise<void> {
    try {
      await apiClient.delete(`${this.baseUrl}/clients/${encodeURIComponent(clientId)}`);
    } catch (error: any) {
      const errorMessage = error.response?.data?.error_description || 
                          error.response?.data?.message || 
                          error.message || 
                          'Failed to delete client';
      throw new Error(errorMessage);
    }
  }

  // Authorization Flow
  static async authorize(request: AuthorizeRequest): Promise<void> {
    try {
      // ユーザー情報をローカルストレージから取得
      const userDataStr = localStorage.getItem('user');
      const userData = userDataStr ? JSON.parse(userDataStr) : null;
      
      console.log('OAuth2Service.authorize: User data:', userData);
      console.log('OAuth2Service.authorize: Request:', request);
      
      // Build authorization URL for direct browser navigation
      const params = new URLSearchParams({
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        response_type: request.response_type,
        scope: request.scope,
        ...(request.state && { state: request.state }),
        ...(request.code_challenge && { code_challenge: request.code_challenge }),
        ...(request.code_challenge_method && { code_challenge_method: request.code_challenge_method }),
      });
      
      // For OAuth2 authorization, we need to navigate the browser directly
      // instead of using AJAX requests, because the server will perform redirects
      
      // Navigate via API Gateway for centralized request handling
      const authUrl = `http://localhost:8080/api/v1/oauth2/authorize?${params.toString()}`;
      
      console.log('OAuth2Service.authorize: Navigating via API Gateway:', authUrl);
      console.log('OAuth2Service.authorize: User ID being passed:', userData?.id);
      
      // Navigate directly to the authorization endpoint
      window.location.href = authUrl;
      
    } catch (error: any) {
      console.error('OAuth2Service.authorize: Error details:', error);
      const errorMessage = error.response?.data?.error_description || 
                          error.response?.data?.error || 
                          error.message || 
                          'Authorization failed';
      throw new Error(errorMessage);
    }
  }

  // Token Exchange
  static async exchangeToken(request: TokenRequest): Promise<TokenResponse> {
    const formData = new URLSearchParams();
    formData.append('grant_type', request.grant_type);
    formData.append('client_id', request.client_id);
    
    if (request.client_secret) {
      formData.append('client_secret', request.client_secret);
    }
    if (request.code) {
      formData.append('code', request.code);
    }
    if (request.redirect_uri) {
      formData.append('redirect_uri', request.redirect_uri);
    }
    if (request.code_verifier) {
      formData.append('code_verifier', request.code_verifier);
    }
    if (request.refresh_token) {
      formData.append('refresh_token', request.refresh_token);
    }
    if (request.scope) {
      formData.append('scope', request.scope);
    }

    const response = await fetch(`${this.baseUrl}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.error || 'Token exchange failed');
    }

    return response.json();
  }

  // Token Introspection
  static async introspectToken(token: string): Promise<any> {
    const formData = new URLSearchParams();
    formData.append('token', token);

    const response = await fetch(`${this.baseUrl}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(localStorage.getItem('accessToken') && { 
          'Authorization': `Bearer ${localStorage.getItem('accessToken')}` 
        }),
      },
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.error || 'Token introspection failed');
    }

    return response.json();
  }

  // Token Revocation
  static async revokeToken(token: string, clientId: string, clientSecret?: string): Promise<void> {
    const formData = new URLSearchParams();
    formData.append('token', token);
    formData.append('client_id', clientId);
    
    if (clientSecret) {
      formData.append('client_secret', clientSecret);
    }

    const response = await fetch(`${this.baseUrl}/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.error || 'Token revocation failed');
    }
  }

  // PKCE Helper Functions
  static generateCodeVerifier(length: number = 128): string {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let text = '';
    for (let i = 0; i < length; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
  }

  static async generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to base64url
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Authorization URL Builder
  static buildAuthorizationUrl(params: {
    client_id: string;
    redirect_uri: string;
    scope: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
  }): string {
    const baseUrl = `${window.location.origin}/oauth/authorize`;
    const searchParams = new URLSearchParams({
      response_type: 'code',
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      scope: params.scope,
    });

    if (params.state) {
      searchParams.append('state', params.state);
    }
    if (params.code_challenge) {
      searchParams.append('code_challenge', params.code_challenge);
      searchParams.append('code_challenge_method', params.code_challenge_method || 'S256');
    }

    return `${baseUrl}?${searchParams.toString()}`;
  }
}

export type { 
  OAuth2Client, 
  CreateClientRequest, 
  CreateClientResponse,
  AuthorizeRequest,
  TokenRequest,
  TokenResponse 
};