/**
 * React Components for Glen ID Platform Integration
 * 
 * これらのコンポーネントは、React アプリケーションで Glen ID Platform を
 * 簡単に統合するためのサンプル実装です。
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import GlenIdSDK from '../../../sdk/javascript/glen-id-sdk.js';

// Glen ID Context
const GlenIdContext = createContext();

/**
 * Glen ID Provider
 * アプリケーション全体で Glen ID の認証状態を管理
 */
export const GlenIdProvider = ({ children, config }) => {
  const [sdk] = useState(() => new GlenIdSDK(config));
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // SDK イベントリスナーを設定
    const handleInitialized = ({ user }) => {
      setUser(user);
      setIsAuthenticated(!!user);
      setIsLoading(false);
    };

    const handleLoginSuccess = async () => {
      const userInfo = await sdk.fetchUserInfo();
      setUser(userInfo);
      setIsAuthenticated(!!userInfo);
      setError(null);
    };

    const handleLoggedOut = () => {
      setUser(null);
      setIsAuthenticated(false);
      setError(null);
    };

    const handleTokenExpired = () => {
      setUser(null);
      setIsAuthenticated(false);
      setError('セッションが期限切れです。再度ログインしてください。');
    };

    const handleError = (error) => {
      setError(error.message || 'エラーが発生しました');
      setIsLoading(false);
    };

    sdk.on('initialized', handleInitialized);
    sdk.on('loginSuccess', handleLoginSuccess);
    sdk.on('loggedOut', handleLoggedOut);
    sdk.on('tokenExpired', handleTokenExpired);
    sdk.on('error', handleError);

    // クリーンアップ
    return () => {
      sdk.off('initialized', handleInitialized);
      sdk.off('loginSuccess', handleLoginSuccess);
      sdk.off('loggedOut', handleLoggedOut);
      sdk.off('tokenExpired', handleTokenExpired);
      sdk.off('error', handleError);
    };
  }, [sdk]);

  const login = (options) => {
    setError(null);
    sdk.login(options);
  };

  const logout = async (options) => {
    setError(null);
    await sdk.logout(options);
  };

  const clearError = () => {
    setError(null);
  };

  const value = {
    sdk,
    user,
    isAuthenticated,
    isLoading,
    error,
    login,
    logout,
    clearError
  };

  return (
    <GlenIdContext.Provider value={value}>
      {children}
    </GlenIdContext.Provider>
  );
};

/**
 * Glen ID Context を使用するためのカスタムフック
 */
export const useGlenId = () => {
  const context = useContext(GlenIdContext);
  if (!context) {
    throw new Error('useGlenId must be used within a GlenIdProvider');
  }
  return context;
};

/**
 * ログインボタンコンポーネント
 */
export const LoginButton = ({ children, className, ...props }) => {
  const { login, isLoading } = useGlenId();

  return (
    <button
      onClick={login}
      disabled={isLoading}
      className={`glen-login-btn ${className || ''}`}
      {...props}
    >
      {children || 'Glen ID でログイン'}
    </button>
  );
};

/**
 * ログアウトボタンコンポーネント
 */
export const LogoutButton = ({ children, className, ...props }) => {
  const { logout, isLoading } = useGlenId();

  return (
    <button
      onClick={logout}
      disabled={isLoading}
      className={`glen-logout-btn ${className || ''}`}
      {...props}
    >
      {children || 'ログアウト'}
    </button>
  );
};

/**
 * ユーザー情報表示コンポーネント
 */
export const UserProfile = ({ className }) => {
  const { user, isAuthenticated } = useGlenId();

  if (!isAuthenticated || !user) {
    return null;
  }

  return (
    <div className={`glen-user-profile ${className || ''}`}>
      <div className="user-avatar">
        {user.avatar_url ? (
          <img src={user.avatar_url} alt={user.username} />
        ) : (
          <div className="avatar-placeholder">
            {user.username.charAt(0).toUpperCase()}
          </div>
        )}
      </div>
      <div className="user-info">
        <div className="username">{user.username}</div>
        <div className="email">{user.email}</div>
      </div>
    </div>
  );
};

/**
 * 認証が必要なコンテンツを保護するコンポーネント
 */
export const ProtectedRoute = ({ 
  children, 
  fallback, 
  loginPrompt = true,
  loadingComponent 
}) => {
  const { isAuthenticated, isLoading, login } = useGlenId();

  if (isLoading) {
    return loadingComponent || <div className="glen-loading">読み込み中...</div>;
  }

  if (!isAuthenticated) {
    if (fallback) {
      return fallback;
    }

    if (loginPrompt) {
      return (
        <div className="glen-login-prompt">
          <h2>ログインが必要です</h2>
          <p>このコンテンツを表示するにはログインしてください。</p>
          <LoginButton />
        </div>
      );
    }

    return null;
  }

  return children;
};

/**
 * エラー表示コンポーネント
 */
export const ErrorDisplay = ({ className }) => {
  const { error, clearError } = useGlenId();

  if (!error) {
    return null;
  }

  return (
    <div className={`glen-error ${className || ''}`}>
      <span className="error-message">{error}</span>
      <button onClick={clearError} className="error-close">
        ×
      </button>
    </div>
  );
};

/**
 * 認証状態に基づく条件付きレンダリング
 */
export const ConditionalAuth = ({ authenticated, unauthenticated }) => {
  const { isAuthenticated, isLoading } = useGlenId();

  if (isLoading) {
    return null;
  }

  return isAuthenticated ? authenticated : unauthenticated;
};

/**
 * Glen ID 統合のためのカスタムフック集
 */

/**
 * ユーザーのWebAuthn認証器を管理するフック
 */
export const useWebAuthnCredentials = () => {
  const { sdk } = useGlenId();
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchCredentials = async () => {
    setLoading(true);
    try {
      const creds = await sdk.getWebAuthnCredentials();
      setCredentials(creds);
    } catch (error) {
      console.error('Failed to fetch WebAuthn credentials:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, [sdk]);

  return {
    credentials,
    loading,
    refresh: fetchCredentials
  };
};

/**
 * ソーシャルアカウント連携を管理するフック
 */
export const useSocialAccounts = () => {
  const { sdk } = useGlenId();
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchAccounts = async () => {
    setLoading(true);
    try {
      const accts = await sdk.getSocialAccounts();
      setAccounts(accts);
    } catch (error) {
      console.error('Failed to fetch social accounts:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAccounts();
  }, [sdk]);

  return {
    accounts,
    loading,
    refresh: fetchAccounts
  };
};

/**
 * APIキー管理フック
 */
export const useApiKeys = () => {
  const { sdk } = useGlenId();
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchTokens = async () => {
    setLoading(true);
    try {
      const tkns = await sdk.getTokens();
      setTokens(tkns);
    } catch (error) {
      console.error('Failed to fetch tokens:', error);
    } finally {
      setLoading(false);
    }
  };

  const createToken = async (tokenData) => {
    setLoading(true);
    try {
      const newToken = await sdk.createToken(tokenData);
      if (newToken) {
        await fetchTokens(); // リストを更新
      }
      return newToken;
    } catch (error) {
      console.error('Failed to create token:', error);
      return null;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTokens();
  }, [sdk]);

  return {
    tokens,
    loading,
    createToken,
    refresh: fetchTokens
  };
};