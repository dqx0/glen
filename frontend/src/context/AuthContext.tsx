import React, { createContext, useContext, useEffect, useState } from 'react';
import { UserService } from '../services/userService';
import { AuthService } from '../services/authService';
import type { User, UserContextType } from '../types/user';

const AuthContext = createContext<UserContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // 初期化時にローカルストレージからユーザー情報を読み込み
    const storedUser = UserService.getStoredUser();
    const token = AuthService.getStoredToken();

    if (storedUser && token && !AuthService.isTokenExpired()) {
      setUser(storedUser);
    } else if (token) {
      // トークンがあるがユーザー情報がない場合、APIから取得
      loadUserData();
    }

    setLoading(false);
  }, []);

  const loadUserData = async () => {
    try {
      console.log('AuthContext: loadUserData() called');
      const userData = await UserService.getUser();
      console.log('AuthContext: User data loaded:', userData);
      setUser(userData);
      UserService.storeUser(userData);
      console.log('AuthContext: User state set and stored');
    } catch (error) {
      console.error('AuthContext: Failed to load user data:', error);
      // エラーの場合、ローカルデータをクリア
      AuthService.clearTokens();
      UserService.clearUser();
      console.log('AuthContext: Cleared tokens and user data due to error');
    }
  };

  const login = async (username: string, password: string): Promise<void> => {
    setLoading(true);
    setError(null);

    try {
      console.log('AuthContext: Starting login process...');
      
      // ユーザーログインAPI
      const userResponse = await UserService.login({ username, password });
      console.log('AuthContext: User login successful:', userResponse.user);
      
      // JWTトークン発行API
      const authResponse = await AuthService.login({
        user_id: userResponse.user.id,
        username: userResponse.user.username,
        session_name: 'web-session',
        scopes: ['read', 'write'],
      });
      console.log('AuthContext: JWT token received');

      // ユーザー情報とトークンを保存
      setUser(userResponse.user);
      UserService.storeUser(userResponse.user);
      AuthService.storeTokens(authResponse);
      
      // ユーザー名もローカルストレージに保存（トークンリフレッシュ用）
      localStorage.setItem('username', userResponse.user.username);
      
      console.log('AuthContext: Login complete, user state set to:', userResponse.user);
      
    } catch (error: any) {
      console.error('AuthContext: Login error details:', error);
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'ログインに失敗しました';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
      console.log('AuthContext: Loading set to false');
    }
  };

  const register = async (username: string, email: string, password: string): Promise<void> => {
    setLoading(true);
    setError(null);

    try {
      await UserService.register({ username, email, password });
      
      // 登録後、自動的にログイン
      await login(username, password);
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || error.message || 'アカウント作成に失敗しました';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    AuthService.clearTokens();
    UserService.clearUser();
    localStorage.removeItem('username');
    setError(null);
  };

  const refreshUser = async () => {
    console.log('AuthContext: refreshUser() called');
    await loadUserData();
    console.log('AuthContext: refreshUser() completed, current user:', user);
  };

  const setUserData = (userData: User) => {
    console.log('AuthContext: setUserData() called with:', userData);
    setUser(userData);
    console.log('AuthContext: User state updated');
  };

  const loginWithWebAuthn = async (userId: string): Promise<void> => {
    setLoading(true);
    setError(null);

    try {
      console.log('AuthContext: Starting WebAuthn login process...');
      
      // まずJWTトークンを発行（WebAuthn認証後なので認証済み状態）
      const authResponse = await AuthService.login({
        user_id: userId,
        username: 'webauthn-user', // 仮のユーザー名（トークン取得後に実際のユーザー名で更新）
        session_name: 'webauthn-session',
        scopes: ['read', 'write'],
      });
      console.log('AuthContext: JWT token received for WebAuthn');

      // トークンを先に設定（これでAPI認証が通る）
      AuthService.storeTokens(authResponse);
      
      // トークンが設定された状態でユーザー情報を取得
      const userData = await UserService.getUserById(userId);
      console.log('AuthContext: User data loaded for WebAuthn:', userData);
      console.log('AuthContext: User data fields - created_at:', userData.created_at, 'updated_at:', userData.updated_at);

      // ユーザー情報を保存（パスワードログインと同じパターン）
      setUser(userData);
      UserService.storeUser(userData);
      
      // ユーザー名もローカルストレージに保存
      localStorage.setItem('username', userData.username);
      
      console.log('AuthContext: WebAuthn login complete, user state set to:', userData);
      
    } catch (error: any) {
      console.error('AuthContext: WebAuthn login error details:', error);
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'WebAuthn ログインに失敗しました';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
      console.log('AuthContext: WebAuthn loading set to false');
    }
  };

  const value: UserContextType = {
    user,
    login,
    loginWithWebAuthn,
    register,
    logout,
    refreshUser,
    setUserData,
    loading,
    error,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};