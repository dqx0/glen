import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { WebAuthnService } from '../services/webauthnService';
import { AuthService } from '../services/authService';
import { UserService } from '../services/userService';
import WebAuthnLoginButton from './WebAuthnLoginButton';
import type { AuthenticationFinishResponse } from '../types/webauthn';
import type { User } from '../types/user';

interface WebAuthnSectionProps {
  username: string;
  onError?: (error: string) => void;
  disabled?: boolean;
}

const WebAuthnSection: React.FC<WebAuthnSectionProps> = ({
  username,
  onError,
  disabled = false,
}) => {
  const [isSupported, setIsSupported] = useState(false);
  const [isPlatformSupported, setIsPlatformSupported] = useState(false);
  const navigate = useNavigate();
  const { user, setUserData } = useAuth();

  useEffect(() => {
    checkWebAuthnSupport();
  }, []);

  const checkWebAuthnSupport = async () => {
    const supported = WebAuthnService.isSupported();
    setIsSupported(supported);

    if (supported) {
      const platformSupported = await WebAuthnService.isPlatformAuthenticatorSupported();
      setIsPlatformSupported(platformSupported);
    }
  };

  const handleWebAuthnSuccess = async (response: AuthenticationFinishResponse) => {
    try {
      console.log('WebAuthn認証成功:', response);
      
      if (!response.user_id) {
        throw new Error('User ID not found in authentication response');
      }

      // まず、WebAuthn認証レスポンスに基づいてJWTトークンを発行
      console.log('JWTトークンを発行中...');
      const authResponse = await AuthService.login({
        user_id: response.user_id,
        username: 'webauthn-user',
        session_name: 'webauthn-session',
        scopes: ['read', 'write'],
      });
      console.log('JWTトークン発行成功');

      // トークンを保存（これでAPIアクセスが可能になる）
      AuthService.storeTokens(authResponse);
      console.log('トークン保存完了');
      
      // トークンが設定された状態でユーザー情報を取得
      console.log('ユーザー情報を取得中...');
      const userData = await UserService.getUserById(response.user_id);
      console.log('ユーザー情報取得成功:', userData);

      // ユーザー情報を保存
      UserService.storeUser(userData);
      localStorage.setItem('user_id', response.user_id);
      localStorage.setItem('username', userData.username);
      console.log('ユーザー情報保存完了');

      // AuthContextの状態を更新
      console.log('AuthContextの状態を更新中...');
      setUserData(userData);
      console.log('AuthContext更新完了、current user:', userData);

      // 少し待ってからダッシュボードにリダイレクト
      console.log('ダッシュボードにリダイレクト中...');
      setTimeout(() => {
        navigate('/dashboard');
      }, 100);
      
    } catch (error: any) {
      console.error('Post-WebAuthn authentication failed:', error);
      onError?.(error.message || 'ログイン処理に失敗しました');
    }
  };

  const handleWebAuthnError = (error: string) => {
    onError?.(error);
  };

  // 既にログインしている場合は表示しない
  if (user) {
    return null;
  }

  // WebAuthnがサポートされていない場合は表示しない
  if (!isSupported) {
    return null;
  }

  return (
    <div>
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        margin: '1.5rem 0',
        textAlign: 'center' 
      }}>
        <div style={{ 
          flex: 1, 
          height: '1px', 
          backgroundColor: '#e5e7eb' 
        }}></div>
        <span style={{ 
          padding: '0 1rem', 
          fontSize: '0.875rem', 
          color: '#6b7280',
          backgroundColor: 'white'
        }}>
          または
        </span>
        <div style={{ 
          flex: 1, 
          height: '1px', 
          backgroundColor: '#e5e7eb' 
        }}></div>
      </div>

      <div style={{ marginBottom: '1rem' }}>
        <WebAuthnLoginButton
          username={username}
          onSuccess={handleWebAuthnSuccess}
          onError={handleWebAuthnError}
          disabled={disabled || !username.trim()}
        />
      </div>

      {isPlatformSupported && (
        <div style={{
          backgroundColor: '#f0fdf4',
          border: '1px solid #bbf7d0',
          borderRadius: '0.5rem',
          padding: '0.75rem',
          fontSize: '0.75rem',
          color: '#166534',
          textAlign: 'center'
        }}>
          <div style={{ fontWeight: 500, marginBottom: '0.25rem' }}>
            🔒 このデバイスは生体認証をサポートしています
          </div>
          <div>
            Touch ID、Face ID、またはWindows Helloを使用してログインできます
          </div>
        </div>
      )}
    </div>
  );
};

export default WebAuthnSection;