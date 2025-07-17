import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { WebAuthnService } from '../services/webauthnService';
import WebAuthnLoginButton from './WebAuthnLoginButton';
import type { AuthenticationFinishResponse } from '../types/webauthn';

interface WebAuthnSectionProps {
  onError?: (error: string) => void;
  disabled?: boolean;
}

const WebAuthnSection: React.FC<WebAuthnSectionProps> = ({
  onError,
  disabled = false,
}) => {
  const [isSupported, setIsSupported] = useState(false);
  const [isPlatformSupported, setIsPlatformSupported] = useState(false);
  const navigate = useNavigate();
  const { user, loginWithWebAuthn } = useAuth();

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

      // AuthContextのWebAuthn専用ログイン関数を使用（パスワードログインと同じパターン）
      await loginWithWebAuthn(response.user_id);

      // 少し待ってからダッシュボードにリダイレクト
      setTimeout(() => {
        navigate('/dashboard');
      }, 100);
      
    } catch (error: any) {
      console.error('WebAuthn login failed:', error);
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
        {/* パスワードレス認証ボタンのみ */}
        <WebAuthnLoginButton
          onSuccess={handleWebAuthnSuccess}
          onError={handleWebAuthnError}
          disabled={disabled}
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
            パスワードレスログインでは、ユーザー名入力不要で認証器が自動的にアカウントを識別します
          </div>
        </div>
      )}
    </div>
  );
};

export default WebAuthnSection;