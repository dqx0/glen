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
      const userData = await UserService.getUser();
      setUser(userData);
      UserService.storeUser(userData);
    } catch (error) {
      console.error('Failed to load user data:', error);
      // エラーの場合、ローカルデータをクリア
      AuthService.clearTokens();
      UserService.clearUser();
    }
  };

  const login = async (username: string, password: string): Promise<void> => {
    setLoading(true);
    setError(null);

    try {
      // ユーザーログインAPI
      const userResponse = await UserService.login({ username, password });
      
      // JWTトークン発行API
      const authResponse = await AuthService.login({
        user_id: userResponse.user.id,
        username: userResponse.user.username,
        session_name: 'web-session',
        scopes: ['read', 'write'],
      });

      // ユーザー情報とトークンを保存
      setUser(userResponse.user);
      UserService.storeUser(userResponse.user);
      AuthService.storeTokens(authResponse);
      
      // ユーザー名もローカルストレージに保存（トークンリフレッシュ用）
      localStorage.setItem('username', userResponse.user.username);
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'ログインに失敗しました';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
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
    await loadUserData();
  };

  const setUserData = (userData: User) => {
    setUser(userData);
  };

  const loginWithWebAuthn = async (userId: string): Promise<void> => {
    setLoading(true);
    setError(null);

    try {
      // まずJWTトークンを発行（WebAuthn認証後なので認証済み状態）
      const authResponse = await AuthService.login({
        user_id: userId,
        username: 'webauthn-user', // 仮のユーザー名（トークン取得後に実際のユーザー名で更新）
        session_name: 'webauthn-session',
        scopes: ['read', 'write'],
      });

      // トークンを先に設定（これでAPI認証が通る）
      AuthService.storeTokens(authResponse);
      
      // トークンが設定された状態でユーザー情報を取得
      const userData = await UserService.getUserById(userId);

      // ユーザー情報を保存（パスワードログインと同じパターン）
      setUser(userData);
      UserService.storeUser(userData);
      
      // ユーザー名もローカルストレージに保存
      localStorage.setItem('username', userData.username);
      
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || error.response?.data?.message || error.message || 'WebAuthn ログインに失敗しました';
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // isAuthenticated の計算
  const isAuthenticated = !!user && !!AuthService.getStoredToken() && !AuthService.isTokenExpired();

  const value: UserContextType = {
    user,
    isAuthenticated,
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