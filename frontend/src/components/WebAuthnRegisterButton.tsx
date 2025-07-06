import { useState } from 'react';
import { WebAuthnService } from '../services/webauthnService';
import type { WebAuthnCredential } from '../types/webauthn';
import { FingerPrintIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';

interface WebAuthnRegisterButtonProps {
  userId: string;
  username: string;
  displayName?: string;
  onSuccess?: (credential: WebAuthnCredential) => void;
  onError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
}

const WebAuthnRegisterButton: React.FC<WebAuthnRegisterButtonProps> = ({
  userId,
  username,
  displayName,
  onSuccess,
  onError,
  disabled = false,
  className = '',
}) => {
  const [isRegistering, setIsRegistering] = useState(false);
  const [credentialName, setCredentialName] = useState('');
  const [showNameInput, setShowNameInput] = useState(false);
  const [isSupported] = useState(WebAuthnService.isSupported());

  const handleRegister = async () => {
    if (!credentialName.trim()) {
      setShowNameInput(true);
      return;
    }

    if (!isSupported) {
      onError?.('WebAuthnはこのブラウザでサポートされていません');
      return;
    }

    try {
      setIsRegistering(true);
      
      const credential = await WebAuthnService.registerCredential(
        userId,
        username,
        credentialName.trim(),
        displayName
      );

      onSuccess?.(credential);
      setCredentialName('');
      setShowNameInput(false);
      
    } catch (error: any) {
      console.error('WebAuthn registration failed:', error);
      onError?.(error.message || 'WebAuthn登録に失敗しました');
    } finally {
      setIsRegistering(false);
    }
  };

  const startRegistration = () => {
    if (!isSupported) {
      onError?.('WebAuthnはこのブラウザでサポートされていません');
      return;
    }
    setShowNameInput(true);
  };

  const cancelRegistration = () => {
    setShowNameInput(false);
    setCredentialName('');
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
        color: '#92400e'
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

  if (showNameInput) {
    return (
      <div style={{
        backgroundColor: '#f9fafb',
        border: '1px solid #e5e7eb',
        borderRadius: '0.5rem',
        padding: '1rem'
      }}>
        <h4 style={{
          fontSize: '0.875rem',
          fontWeight: 500,
          color: '#1f2937',
          marginBottom: '0.75rem'
        }}>
          WebAuthn認証器を登録
        </h4>
        <p style={{
          fontSize: '0.75rem',
          color: '#6b7280',
          marginBottom: '1rem'
        }}>
          指紋認証、顔認証、またはセキュリティキーを使用してパスワードレス認証を設定できます。
        </p>
        <div style={{ marginBottom: '1rem' }}>
          <label style={{
            display: 'block',
            fontSize: '0.875rem',
            fontWeight: 500,
            color: '#374151',
            marginBottom: '0.5rem'
          }}>
            認証器名
          </label>
          <input
            type="text"
            value={credentialName}
            onChange={(e) => setCredentialName(e.target.value)}
            placeholder="例：iPhone Touch ID、YubiKey等"
            maxLength={100}
            className="form-input"
            disabled={isRegistering}
            style={{ width: '100%' }}
          />
        </div>
        <div style={{
          display: 'flex',
          gap: '0.5rem',
          flexWrap: 'wrap'
        }}>
          <button
            onClick={handleRegister}
            disabled={isRegistering || !credentialName.trim()}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              padding: '0.5rem 1rem',
              backgroundColor: 'var(--color-primary-600)',
              color: 'white',
              border: 'none',
              borderRadius: '0.375rem',
              fontSize: '0.875rem',
              fontWeight: 500,
              cursor: isRegistering || !credentialName.trim() ? 'not-allowed' : 'pointer',
              opacity: isRegistering || !credentialName.trim() ? 0.5 : 1
            }}
          >
            <FingerPrintIcon style={{ 
              width: '1rem', 
              height: '1rem', 
              marginRight: '0.5rem' 
            }} />
            {isRegistering ? '登録中...' : '認証器を登録'}
          </button>
          <button
            onClick={cancelRegistration}
            disabled={isRegistering}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: '#f3f4f6',
              color: '#374151',
              border: 'none',
              borderRadius: '0.375rem',
              fontSize: '0.875rem',
              fontWeight: 500,
              cursor: isRegistering ? 'not-allowed' : 'pointer',
              opacity: isRegistering ? 0.5 : 1
            }}
          >
            キャンセル
          </button>
        </div>
      </div>
    );
  }

  return (
    <button
      onClick={startRegistration}
      disabled={disabled}
      className={`
        inline-flex items-center px-4 py-2 border border-transparent 
        text-sm font-medium rounded-lg focus:outline-none focus:ring-2 
        focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 
        disabled:cursor-not-allowed
        ${className}
      `}
      style={{
        backgroundColor: '#8b5cf6',
        color: 'white',
        border: 'none'
      }}
    >
      <FingerPrintIcon style={{ 
        width: '1.25rem', 
        height: '1.25rem', 
        marginRight: '0.5rem' 
      }} />
      WebAuthn認証器を追加
    </button>
  );
};

export default WebAuthnRegisterButton;