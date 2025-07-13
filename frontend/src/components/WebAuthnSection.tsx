import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { WebAuthnService } from '../services/webauthnService';
import WebAuthnLoginButton from './WebAuthnLoginButton';
import type { AuthenticationFinishResponse } from '../types/webauthn';

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
  const { user, loginWithWebAuthn } = useAuth();

  useEffect(() => {
    checkWebAuthnSupport();
  }, []);

  const checkWebAuthnSupport = async () => {
    const supported = WebAuthnService.isSupported();
    console.log('WebAuthnSection: WebAuthn support check:', supported);
    setIsSupported(supported);

    if (supported) {
      const platformSupported = await WebAuthnService.isPlatformAuthenticatorSupported();
      console.log('WebAuthnSection: Platform authenticator support:', platformSupported);
      setIsPlatformSupported(platformSupported);
    }
  };

  const handleWebAuthnSuccess = async (response: AuthenticationFinishResponse) => {
    try {
      console.log('WebAuthn認証成功:', response);
      
      if (!response.user_id) {
        throw new Error('User ID not found in authentication response');
      }

      // AuthContextのWebAuthn専用ログイン関数を使用（パスワードログインと同じパターン）
      console.log('WebAuthn ログイン処理を開始...');
      await loginWithWebAuthn(response.user_id);
      console.log('WebAuthn ログイン処理完了');

      // 少し待ってからダッシュボードにリダイレクト
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
    console.log('WebAuthnSection: User already logged in, hiding WebAuthn section');
    return null;
  }

  // WebAuthnがサポートされていない場合は表示しない
  if (!isSupported) {
    console.log('WebAuthnSection: WebAuthn not supported, hiding section');
    return null;
  }

  console.log('WebAuthnSection: Rendering WebAuthn section', { username, disabled, isSupported, isPlatformSupported });

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