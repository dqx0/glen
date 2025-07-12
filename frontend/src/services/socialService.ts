import apiClient from '../api/client';
import type {
  SocialProvider,
  AuthorizeRequest,
  AuthorizeResponse,
  CallbackRequest,
  CallbackResponse,
  SocialLoginResponse,
  ProvidersResponse,
  SocialAccountsResponse,
  UnlinkAccountRequest,
} from '../types/social';

export class SocialService {
  private static readonly SOCIAL_BASE_URL = '/api/v1/social';

  // 利用可能なソーシャルプロバイダーを取得
  static async getProviders(): Promise<ProvidersResponse> {
    const response = await apiClient.get<ProvidersResponse>(
      `${this.SOCIAL_BASE_URL}/providers`
    );
    return response.data;
  }

  // OAuth2認証URLを生成
  static async authorize(request: AuthorizeRequest): Promise<AuthorizeResponse> {
    const response = await apiClient.post<AuthorizeResponse>(
      `${this.SOCIAL_BASE_URL}/authorize`,
      request
    );
    return response.data;
  }

  // OAuth2コールバック処理（アカウント連携用）
  static async callback(request: CallbackRequest): Promise<CallbackResponse> {
    const response = await apiClient.post<CallbackResponse>(
      `${this.SOCIAL_BASE_URL}/callback`,
      request
    );
    return response.data;
  }

  // ソーシャルログイン処理
  static async socialLogin(request: CallbackRequest): Promise<SocialLoginResponse> {
    const response = await apiClient.post<SocialLoginResponse>(
      `${this.SOCIAL_BASE_URL}/login`,
      request
    );
    return response.data;
  }

  // ユーザーの連携ソーシャルアカウント一覧を取得
  static async getSocialAccounts(): Promise<SocialAccountsResponse> {
    const response = await apiClient.get<SocialAccountsResponse>(
      `${this.SOCIAL_BASE_URL}/accounts`
    );
    return response.data;
  }

  // ソーシャルアカウントの連携を解除
  static async unlinkAccount(request: UnlinkAccountRequest): Promise<void> {
    await apiClient.delete(`${this.SOCIAL_BASE_URL}/accounts/${request.account_id}`);
  }

  // OAuth2認証フローを開始するユーティリティ
  static async startOAuth2Flow(provider: SocialProvider): Promise<void> {
    try {
      const redirectUri = `${window.location.origin}/auth/callback`;
      const state = this.generateState();
      
      // 認証URLを取得
      const authResponse = await this.authorize({
        provider,
        redirect_uri: redirectUri,
        state,
      });

      // stateをセッションストレージに保存
      sessionStorage.setItem('oauth2_state', state);
      sessionStorage.setItem('oauth2_provider', provider);
      sessionStorage.setItem('oauth2_redirect_uri', redirectUri);

      // 認証ページにリダイレクト（バックエンドのレスポンス構造に合わせる）
      const authUrl = authResponse.authorization_url || authResponse.auth_url;
      if (!authUrl) {
        throw new Error('Authorization URL not found in response');
      }
      window.location.href = authUrl;
    } catch (error) {
      console.error(`Failed to start OAuth2 flow for ${provider}:`, error);
      throw error;
    }
  }

  // OAuth2コールバック処理のユーティリティ
  static async handleOAuth2Callback(): Promise<CallbackResponse> {
    // 重複処理を防ぐ
    const processingKey = 'oauth2_processing';
    if (sessionStorage.getItem(processingKey) === 'true') {
      throw new Error('OAuth2 callback already processing');
    }
    sessionStorage.setItem(processingKey, 'true');

    try {
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');
      const state = urlParams.get('state');
      const error = urlParams.get('error');

      console.log('OAuth2 callback parameters:', { code, state, error });

      if (error) {
        throw new Error(`OAuth2 error: ${error}`);
      }

      if (!code || !state) {
        throw new Error('Missing code or state parameter');
      }

      // 保存されたstateと比較
      const savedState = sessionStorage.getItem('oauth2_state');
      const savedProvider = sessionStorage.getItem('oauth2_provider') as SocialProvider;
      const savedRedirectUri = sessionStorage.getItem('oauth2_redirect_uri');

      console.log('Saved OAuth2 data:', { savedState, savedProvider, savedRedirectUri });

      if (state !== savedState) {
        throw new Error('Invalid state parameter');
      }

      if (!savedProvider || !savedRedirectUri) {
        throw new Error('Missing OAuth2 session data');
      }

      // コールバック処理
      console.log('Calling callback API...');
      const callbackResponse = await this.callback({
        provider: savedProvider,
        code,
        state,
        redirect_uri: savedRedirectUri,
      });

      console.log('Callback API response:', callbackResponse);

      // セッションデータをクリア
      sessionStorage.removeItem('oauth2_state');
      sessionStorage.removeItem('oauth2_provider');
      sessionStorage.removeItem('oauth2_redirect_uri');
      sessionStorage.removeItem('oauth2_mode');

      return callbackResponse;
    } catch (error) {
      // エラー時もセッションデータをクリア
      sessionStorage.removeItem('oauth2_state');
      sessionStorage.removeItem('oauth2_provider');
      sessionStorage.removeItem('oauth2_redirect_uri');
      sessionStorage.removeItem('oauth2_mode');
      throw error;
    } finally {
      // 処理完了フラグをクリア
      sessionStorage.removeItem(processingKey);
    }
  }

  // ランダムなstate文字列を生成
  static generateState(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // プロバイダーごとのブランド情報を取得
  static getProviderInfo(provider: SocialProvider) {
    const providerInfo = {
      google: {
        name: 'Google',
        color: '#4285f4',
        icon: '🌐',
        bgColor: '#4285f4',
        textColor: '#ffffff',
      },
      github: {
        name: 'GitHub',
        color: '#333333',
        icon: '🐙',
        bgColor: '#333333',
        textColor: '#ffffff',
      },
      discord: {
        name: 'Discord',
        color: '#5865f2',
        icon: '🎮',
        bgColor: '#5865f2',
        textColor: '#ffffff',
      },
    };

    return providerInfo[provider];
  }
}