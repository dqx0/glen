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
  const { user, refreshUser } = useAuth();

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
      if (!response.user_id) {
        throw new Error('User ID not found in authentication response');
      }

      // WebAuthn認証レスポンスに基づいてJWTトークンを発行
      // Note: The response now only contains user_id, not complete user info
      const authResponse = await AuthService.login({
        user_id: response.user_id,
        username: 'webauthn-user', // Temporary placeholder
        session_name: 'webauthn-session',
        scopes: ['read', 'write'],
      });

      AuthService.storeTokens(authResponse);
      localStorage.setItem('user_id', response.user_id);

      // Note: ユーザー情報の更新は次回ページ読み込み時にAuthContextの初期化で処理される
      // 今はトークンが保存されているので、ダッシュボードに直接遷移

      // 少し待ってからダッシュボードにリダイレクト（状態の更新を待つ）
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