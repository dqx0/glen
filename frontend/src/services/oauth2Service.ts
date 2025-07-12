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

export class OAuth2Service {
  private static baseUrl = '/api/v1/oauth2';

  private static getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('accessToken');
    return {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
    };
  }

  // Client Management
  static async createClient(request: CreateClientRequest): Promise<CreateClientResponse> {
    const response = await fetch(`${this.baseUrl}/clients`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.message || 'Failed to create client');
    }

    return response.json();
  }

  static async getClients(userId: string): Promise<OAuth2Client[]> {
    const response = await fetch(`${this.baseUrl}/clients?user_id=${encodeURIComponent(userId)}`, {
      headers: this.getAuthHeaders(),
    });

    if (!response.ok) {
      if (response.status === 404) {
        return []; // No clients found
      }
      const error = await response.json();
      throw new Error(error.error_description || error.message || 'Failed to fetch clients');
    }

    const data = await response.json();
    return Array.isArray(data) ? data : [];
  }

  static async getClient(clientId: string): Promise<OAuth2Client> {
    const response = await fetch(`${this.baseUrl}/clients/${encodeURIComponent(clientId)}`, {
      headers: this.getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.message || 'Failed to fetch client');
    }

    return response.json();
  }

  static async deleteClient(clientId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/clients/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.message || 'Failed to delete client');
    }
  }

  // Authorization Flow
  static async authorize(request: AuthorizeRequest): Promise<void> {
    const formData = new URLSearchParams();
    formData.append('client_id', request.client_id);
    formData.append('redirect_uri', request.redirect_uri);
    formData.append('response_type', request.response_type);
    formData.append('scope', request.scope);
    
    if (request.state) {
      formData.append('state', request.state);
    }
    if (request.code_challenge) {
      formData.append('code_challenge', request.code_challenge);
    }
    if (request.code_challenge_method) {
      formData.append('code_challenge_method', request.code_challenge_method);
    }

    const response = await fetch(`${this.baseUrl}/authorize`, {
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
      throw new Error(error.error_description || error.error || 'Authorization failed');
    }

    // 成功時はサーバーがリダイレクトするため、ここには通常到達しない
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