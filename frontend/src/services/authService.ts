import apiClient from '../api/client';
import type {
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  RefreshResponse,
  CreateAPIKeyRequest,
  APIKeyResponse,
  RevokeTokenRequest,
  Token,
  ValidateAPIKeyResponse,
} from '../types/auth';

export class AuthService {
  private static readonly AUTH_BASE_URL = '/api/v1/auth';

  // ログイン
  static async login(request: LoginRequest): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>(
      `${this.AUTH_BASE_URL}/login`,
      request
    );
    return response.data;
  }

  // トークンリフレッシュ
  static async refreshToken(request: RefreshTokenRequest): Promise<RefreshResponse> {
    const response = await apiClient.post<RefreshResponse>(
      `${this.AUTH_BASE_URL}/refresh`,
      request
    );
    return response.data;
  }

  // APIキー作成
  static async createAPIKey(request: CreateAPIKeyRequest): Promise<APIKeyResponse> {
    const response = await apiClient.post<APIKeyResponse>(
      `${this.AUTH_BASE_URL}/api-keys`,
      request
    );
    return response.data;
  }

  // トークン無効化
  static async revokeToken(request: RevokeTokenRequest): Promise<void> {
    await apiClient.post(`${this.AUTH_BASE_URL}/revoke`, request);
  }

  // ユーザーのトークン一覧取得
  static async listTokens(userId: string): Promise<Token[]> {
    const response = await apiClient.get<Token[]>(
      `${this.AUTH_BASE_URL}/tokens?user_id=${userId}`
    );
    return response.data;
  }

  // APIキー検証
  static async validateAPIKey(apiKey: string): Promise<ValidateAPIKeyResponse> {
    const response = await apiClient.post<ValidateAPIKeyResponse>(
      `${this.AUTH_BASE_URL}/validate-api-key`,
      { api_key: apiKey }
    );
    return response.data;
  }

  // ローカルストレージからトークンを取得
  static getStoredToken(): string | null {
    return localStorage.getItem('accessToken');
  }

  // ローカルストレージにトークンを保存
  static storeTokens(loginResponse: LoginResponse): void {
    localStorage.setItem('accessToken', loginResponse.access_token);
    localStorage.setItem('refreshToken', loginResponse.refresh_token);
    localStorage.setItem('tokenExpiresAt', 
      (Date.now() + loginResponse.expires_in * 1000).toString()
    );
  }

  // ローカルストレージからトークンを削除
  static clearTokens(): void {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('tokenExpiresAt');
  }

  // トークンの有効期限をチェック
  static isTokenExpired(): boolean {
    const expiresAt = localStorage.getItem('tokenExpiresAt');
    if (!expiresAt) return true;
    
    return Date.now() >= parseInt(expiresAt);
  }

  // 自動トークンリフレッシュ
  static async autoRefreshToken(): Promise<boolean> {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return false;

    try {
      const response = await this.refreshToken({
        refresh_token: refreshToken,
        username: '', // 実際のアプリケーションでは適切なユーザー名を使用
      });

      // 新しいアクセストークンを保存
      localStorage.setItem('accessToken', response.access_token);
      localStorage.setItem('tokenExpiresAt', 
        (Date.now() + response.expires_in * 1000).toString()
      );

      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      this.clearTokens();
      return false;
    }
  }
}
