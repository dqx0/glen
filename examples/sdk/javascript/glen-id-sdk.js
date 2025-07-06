/**
 * Glen ID Platform JavaScript SDK
 * 
 * このSDKは、Webアプリケーションで Glen ID Platform との統合を簡単にするためのものです。
 * JWTトークンベースの認証、ユーザー情報取得、認証状態管理などの機能を提供します。
 * 
 * @version 1.0.0
 * @author Glen ID Platform Team
 * @license MIT
 */

class GlenIdSDK {
  /**
   * Glen ID SDK インスタンスを作成
   * 
   * @param {Object} config - 設定オブジェクト
   * @param {string} config.baseUrl - Glen ID Platform のベースURL
   * @param {string} config.clientId - クライアントID（将来のOAuth2サポート用）
   * @param {string} [config.redirectUri] - リダイレクトURI
   * @param {string[]} [config.scopes] - 要求するスコープ
   * @param {boolean} [config.debug] - デバッグモードの有効化
   */
  constructor(config) {
    this.config = {
      baseUrl: 'https://glen.dqx0.com',
      apiBaseUrl: 'https://api.glen.dqx0.com/api/v1',
      redirectUri: window.location.origin + '/auth/callback',
      scopes: ['read'],
      debug: false,
      ...config
    };

    this.token = null;
    this.user = null;
    this.isInitialized = false;

    // イベントリスナー
    this.eventListeners = {};

    // 自動初期化
    this.init();
  }

  /**
   * SDKを初期化
   */
  async init() {
    try {
      // ローカルストレージからトークンを復元
      this.token = localStorage.getItem('glen_id_token');

      // URLからトークンを取得（コールバック処理）
      this.handleCallback();

      // トークンが存在する場合、ユーザー情報を取得
      if (this.token) {
        await this.fetchUserInfo();
      }

      this.isInitialized = true;
      this.emit('initialized', { user: this.user, token: this.token });

      this.log('SDK initialized successfully');
    } catch (error) {
      this.log('SDK initialization failed:', error);
      this.emit('error', error);
    }
  }

  /**
   * ログイン開始
   * 
   * @param {Object} [options] - ログインオプション
   * @param {string} [options.redirectUri] - カスタムリダイレクトURI
   * @param {string[]} [options.scopes] - カスタムスコープ
   * @param {string} [options.state] - CSRF保護用のstate
   */
  login(options = {}) {
    const params = new URLSearchParams({
      redirect_uri: options.redirectUri || this.config.redirectUri,
      scopes: (options.scopes || this.config.scopes).join(','),
      state: options.state || this.generateState(),
      client_id: this.config.clientId || 'glen-id-sdk'
    });

    const loginUrl = `${this.config.baseUrl}/login?${params.toString()}`;
    
    this.log('Redirecting to login:', loginUrl);
    this.emit('loginStarted', { url: loginUrl });
    
    window.location.href = loginUrl;
  }

  /**
   * ログアウト
   * 
   * @param {Object} [options] - ログアウトオプション
   * @param {boolean} [options.redirect] - Glen ID Platform のログアウトページにリダイレクトするか
   * @param {string} [options.redirectUri] - ログアウト後のリダイレクト先
   */
  async logout(options = {}) {
    try {
      // サーバーサイドでのログアウト
      if (this.token) {
        await this.apiCall('/auth/logout', {
          method: 'POST'
        });
      }

      // ローカル状態をクリア
      this.clearLocalState();

      this.emit('loggedOut');
      this.log('Logged out successfully');

      // Glen ID Platform のログアウトページにリダイレクト
      if (options.redirect !== false) {
        const logoutUrl = `${this.config.baseUrl}/logout` + 
          (options.redirectUri ? `?redirect_uri=${encodeURIComponent(options.redirectUri)}` : '');
        window.location.href = logoutUrl;
      }
    } catch (error) {
      this.log('Logout failed:', error);
      this.emit('error', error);
      
      // エラーが発生してもローカル状態はクリア
      this.clearLocalState();
    }
  }

  /**
   * コールバック処理
   * ログイン後のリダイレクトでトークンを取得
   */
  handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const error = urlParams.get('error');

    if (error) {
      this.log('Callback error:', error);
      this.emit('loginError', { error });
      return false;
    }

    if (token) {
      this.setToken(token);
      this.log('Token received from callback');
      
      // URLからパラメータを削除
      window.history.replaceState(null, '', window.location.pathname);
      
      this.emit('loginSuccess', { token });
      return true;
    }

    return false;
  }

  /**
   * トークンを設定
   * 
   * @param {string} token - JWTトークン
   */
  setToken(token) {
    this.token = token;
    localStorage.setItem('glen_id_token', token);
    this.emit('tokenChanged', { token });
  }

  /**
   * 現在のトークンを取得
   * 
   * @returns {string|null} 現在のJWTトークン
   */
  getToken() {
    return this.token;
  }

  /**
   * 現在のユーザー情報を取得
   * 
   * @returns {Object|null} ユーザー情報
   */
  getUser() {
    return this.user;
  }

  /**
   * 認証状態を確認
   * 
   * @returns {boolean} 認証済みかどうか
   */
  isAuthenticated() {
    return !!(this.token && this.user);
  }

  /**
   * ユーザー情報を取得
   * 
   * @param {boolean} [force=false] - キャッシュを無視して強制取得
   * @returns {Promise<Object|null>} ユーザー情報
   */
  async fetchUserInfo(force = false) {
    if (!this.token) {
      return null;
    }

    if (this.user && !force) {
      return this.user;
    }

    try {
      const response = await this.apiCall('/users/me');
      if (response.ok) {
        const data = await response.json();
        this.user = data.user || data;
        this.emit('userInfoUpdated', { user: this.user });
        return this.user;
      } else if (response.status === 401) {
        // トークンが無効
        this.clearLocalState();
        this.emit('tokenExpired');
        return null;
      } else {
        throw new Error(`Failed to fetch user info: ${response.status}`);
      }
    } catch (error) {
      this.log('Failed to fetch user info:', error);
      this.emit('error', error);
      return null;
    }
  }

  /**
   * 認証が必要なAPI呼び出し
   * 
   * @param {string} endpoint - APIエンドポイント
   * @param {Object} [options] - fetchオプション
   * @returns {Promise<Response>} fetch レスポンス
   */
  async apiCall(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${this.config.apiBaseUrl}${endpoint}`;
    
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const fetchOptions = {
      ...options,
      headers
    };

    this.log('API call:', url, fetchOptions);

    const response = await fetch(url, fetchOptions);

    // トークンが無効な場合の自動処理
    if (response.status === 401 && this.token) {
      this.log('Token expired, clearing local state');
      this.clearLocalState();
      this.emit('tokenExpired');
    }

    return response;
  }

  /**
   * トークンの有効性を検証
   * 
   * @returns {Promise<boolean>} トークンが有効かどうか
   */
  async validateToken() {
    if (!this.token) {
      return false;
    }

    try {
      const response = await this.apiCall('/auth/verify');
      return response.ok;
    } catch (error) {
      this.log('Token validation failed:', error);
      return false;
    }
  }

  /**
   * トークンを更新
   * 
   * @param {string} [refreshToken] - リフレッシュトークン
   * @returns {Promise<boolean>} 更新成功かどうか
   */
  async refreshToken(refreshToken) {
    try {
      const response = await fetch(`${this.config.apiBaseUrl}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          refresh_token: refreshToken || localStorage.getItem('glen_id_refresh_token')
        })
      });

      if (response.ok) {
        const data = await response.json();
        this.setToken(data.access_token);
        
        if (data.refresh_token) {
          localStorage.setItem('glen_id_refresh_token', data.refresh_token);
        }

        this.emit('tokenRefreshed', { token: data.access_token });
        return true;
      } else {
        this.clearLocalState();
        this.emit('refreshFailed');
        return false;
      }
    } catch (error) {
      this.log('Token refresh failed:', error);
      this.emit('error', error);
      return false;
    }
  }

  /**
   * WebAuthn 認証器の一覧を取得
   * 
   * @returns {Promise<Array>} 認証器リスト
   */
  async getWebAuthnCredentials() {
    try {
      const response = await this.apiCall('/webauthn/credentials');
      if (response.ok) {
        const data = await response.json();
        return data.credentials || [];
      }
      return [];
    } catch (error) {
      this.log('Failed to get WebAuthn credentials:', error);
      return [];
    }
  }

  /**
   * ソーシャルアカウント連携状況を取得
   * 
   * @returns {Promise<Array>} 連携済みアカウントリスト
   */
  async getSocialAccounts() {
    try {
      const response = await this.apiCall('/social/accounts');
      if (response.ok) {
        const data = await response.json();
        return data.accounts || [];
      }
      return [];
    } catch (error) {
      this.log('Failed to get social accounts:', error);
      return [];
    }
  }

  /**
   * APIキー一覧を取得
   * 
   * @returns {Promise<Array>} APIキーリスト
   */
  async getTokens() {
    try {
      const response = await this.apiCall('/tokens');
      if (response.ok) {
        const data = await response.json();
        return data.tokens || [];
      }
      return [];
    } catch (error) {
      this.log('Failed to get tokens:', error);
      return [];
    }
  }

  /**
   * 新しいAPIキーを作成
   * 
   * @param {Object} tokenData - APIキー作成データ
   * @param {string} tokenData.name - APIキー名
   * @param {string[]} tokenData.scopes - スコープ
   * @param {number} [tokenData.expires_in] - 有効期限（秒）
   * @returns {Promise<Object|null>} 作成されたAPIキー情報
   */
  async createToken(tokenData) {
    try {
      const response = await this.apiCall('/tokens', {
        method: 'POST',
        body: JSON.stringify(tokenData)
      });

      if (response.ok) {
        const data = await response.json();
        this.emit('tokenCreated', data);
        return data;
      }
      return null;
    } catch (error) {
      this.log('Failed to create token:', error);
      this.emit('error', error);
      return null;
    }
  }

  /**
   * イベントリスナーを追加
   * 
   * @param {string} event - イベント名
   * @param {Function} callback - コールバック関数
   */
  on(event, callback) {
    if (!this.eventListeners[event]) {
      this.eventListeners[event] = [];
    }
    this.eventListeners[event].push(callback);
  }

  /**
   * イベントリスナーを削除
   * 
   * @param {string} event - イベント名
   * @param {Function} [callback] - 特定のコールバック関数（未指定の場合は全て削除）
   */
  off(event, callback) {
    if (!this.eventListeners[event]) return;

    if (callback) {
      this.eventListeners[event] = this.eventListeners[event].filter(cb => cb !== callback);
    } else {
      delete this.eventListeners[event];
    }
  }

  /**
   * イベントを発火
   * 
   * @param {string} event - イベント名
   * @param {*} data - イベントデータ
   */
  emit(event, data) {
    if (this.eventListeners[event]) {
      this.eventListeners[event].forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          this.log('Event callback error:', error);
        }
      });
    }
  }

  /**
   * ローカル状態をクリア
   */
  clearLocalState() {
    this.token = null;
    this.user = null;
    localStorage.removeItem('glen_id_token');
    localStorage.removeItem('glen_id_refresh_token');
    this.emit('stateCleared');
  }

  /**
   * CSRFトークンを生成
   * 
   * @returns {string} ランダムなstate文字列
   */
  generateState() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  /**
   * デバッグログ出力
   * 
   * @param {...*} args - ログメッセージ
   */
  log(...args) {
    if (this.config.debug) {
      console.log('[GlenIdSDK]', ...args);
    }
  }

  /**
   * SDK のバージョン情報を取得
   * 
   * @returns {string} バージョン番号
   */
  static getVersion() {
    return '1.0.0';
  }
}

// ブラウザ環境での自動エクスポート
if (typeof window !== 'undefined') {
  window.GlenIdSDK = GlenIdSDK;
}

// Node.js 環境でのエクスポート
if (typeof module !== 'undefined' && module.exports) {
  module.exports = GlenIdSDK;
}

// ES6 モジュールとしてのエクスポート
export default GlenIdSDK;