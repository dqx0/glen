import { useState } from 'react';
import { WebAuthnService } from '../services/webauthnService';
import type { AuthenticationFinishResponse } from '../types/webauthn';
import { FingerPrintIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

interface WebAuthnLoginButtonProps {
  username?: string;
  passwordless?: boolean;
  onSuccess?: (response: AuthenticationFinishResponse) => void;
  onError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
}

const WebAuthnLoginButton: React.FC<WebAuthnLoginButtonProps> = ({
  username,
  passwordless = false,
  onSuccess,
  onError,
  disabled = false,
  className = '',
}) => {
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [isSupported] = useState(WebAuthnService.isSupported());

  const handleAuthenticate = async () => {
    if (!isSupported) {
      onError?.('WebAuthnはこのブラウザでサポートされていません');
      return;
    }

    // パスワードレス認証でない場合はユーザー名が必要
    if (!passwordless && (!username || !username.trim())) {
      onError?.('ユーザー名を入力してください');
      return;
    }

    try {
      setIsAuthenticating(true);
      
      // パスワードレス認証またはユーザー名指定認証
      const response = passwordless 
        ? await WebAuthnService.authenticateWithoutUsername()
        : await WebAuthnService.authenticateCredential(username!.trim());
      
      onSuccess?.(response);
      
    } catch (error: any) {
      console.error('WebAuthn authentication failed:', error);
      onError?.(error.message || 'WebAuthn認証に失敗しました');
    } finally {
      setIsAuthenticating(false);
    }
  };

  if (!isSupported) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '0.75rem 1rem',
        backgroundColor: '#fef3c7',
        border: '1px solid #f59e0b',
        borderRadius: '0.5rem',
        fontSize: '0.875rem',
        color: '#92400e',
        width: '100%'
      }}>
        <ExclamationTriangleIcon style={{ 
          width: '1.25rem', 
          height: '1.25rem', 
          marginRight: '0.5rem' 
        }} />
        WebAuthnはサポートされていません
      </div>
    );
  }

  return (
    <button
      onClick={handleAuthenticate}
      disabled={disabled || isAuthenticating || (!passwordless && (!username || !username.trim()))}
      className={`
        w-full flex items-center justify-center px-4 py-3 border border-transparent 
        text-sm font-medium rounded-lg focus:outline-none focus:ring-2 
        focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 
        disabled:cursor-not-allowed hover:transform hover:scale-105
        ${className}
      `}
      style={{
        backgroundColor: passwordless ? '#059669' : '#8b5cf6',
        color: 'white'
      }}
    >
      <FingerPrintIcon style={{ 
        width: '1.25rem', 
        height: '1.25rem', 
        marginRight: '0.75rem' 
      }} />
      {isAuthenticating ? (
        <span>認証中...</span>
      ) : (
        <span>{passwordless ? 'パスワードレスログイン' : 'WebAuthnでログイン'}</span>
      )}
    </button>
  );
};

export default WebAuthnLoginButton;