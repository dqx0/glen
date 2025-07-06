import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { WebAuthnService } from '../services/webauthnService';
import WebAuthnRegisterButton from './WebAuthnRegisterButton';
import type { WebAuthnCredential } from '../types/webauthn';
import { 
  FingerPrintIcon,
  TrashIcon,
  PencilIcon,
  ClockIcon,
  ShieldCheckIcon,
  CheckIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

const WebAuthnCredentialsSection: React.FC = () => {
  const { user } = useAuth();
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSupported] = useState(WebAuthnService.isSupported());
  const [editingCredential, setEditingCredential] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');

  useEffect(() => {
    if (user && isSupported) {
      loadCredentials();
    } else {
      setLoading(false);
    }
  }, [user, isSupported]);

  const loadCredentials = async () => {
    if (!user) return;

    try {
      setLoading(true);
      const response = await WebAuthnService.getCredentials();
      setCredentials(response.credentials);
    } catch (error: any) {
      console.error('Failed to load WebAuthn credentials:', error);
      setError('WebAuthn認証器の読み込みに失敗しました');
    } finally {
      setLoading(false);
    }
  };

  const handleCredentialRegistered = (credential: WebAuthnCredential) => {
    setCredentials(prev => [...prev, credential]);
    setError(null);
  };

  const handleRegistrationError = (errorMessage: string) => {
    setError(errorMessage);
  };

  const handleDeleteCredential = async (credentialId: string) => {
    if (!confirm('この認証器を削除しますか？削除すると、この認証器でのログインができなくなります。')) {
      return;
    }

    try {
      await WebAuthnService.deleteCredential({ credential_id: credentialId });
      setCredentials(prev => prev.filter(cred => cred.id !== credentialId));
    } catch (error: any) {
      console.error('Failed to delete credential:', error);
      setError('認証器の削除に失敗しました');
    }
  };

  const startEditingCredential = (credential: WebAuthnCredential) => {
    setEditingCredential(credential.id);
    setEditingName(credential.name);
  };

  const cancelEditingCredential = () => {
    setEditingCredential(null);
    setEditingName('');
  };

  const saveCredentialName = async (credentialId: string) => {
    if (!editingName.trim()) {
      setError('認証器名を入力してください');
      return;
    }

    try {
      const updatedCredential = await WebAuthnService.updateCredential({
        credential_id: credentialId,
        name: editingName.trim(),
      });

      setCredentials(prev => 
        prev.map(cred => 
          cred.id === credentialId ? updatedCredential : cred
        )
      );

      setEditingCredential(null);
      setEditingName('');
    } catch (error: any) {
      console.error('Failed to update credential:', error);
      setError('認証器名の更新に失敗しました');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('ja-JP');
  };

  const formatLastUsed = (dateString?: string) => {
    if (!dateString) return '未使用';
    const date = new Date(dateString);
    const now = new Date();
    const diffInDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    
    if (diffInDays === 0) return '今日';
    if (diffInDays === 1) return '1日前';
    if (diffInDays < 7) return `${diffInDays}日前`;
    return date.toLocaleDateString('ja-JP');
  };

  if (!isSupported) {
    return (
      <div style={{ 
        backgroundColor: 'white', 
        borderRadius: '0.5rem', 
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '1.5rem' 
      }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          marginBottom: '1rem' 
        }}>
          <FingerPrintIcon style={{ 
            width: '1.5rem', 
            height: '1.5rem', 
            color: '#9ca3af', 
            marginRight: '0.75rem' 
          }} />
          <h3 style={{ 
            fontSize: '1.125rem', 
            fontWeight: 500, 
            color: '#1f2937',
            margin: 0
          }}>
            WebAuthn認証器
          </h3>
        </div>
        <div style={{
          backgroundColor: '#fef3c7',
          border: '1px solid #f59e0b',
          borderRadius: '0.5rem',
          padding: '1rem',
          textAlign: 'center'
        }}>
          <div style={{ 
            fontSize: '0.875rem', 
            color: '#92400e' 
          }}>
            WebAuthnはこのブラウザでサポートされていません
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ 
        backgroundColor: 'white', 
        borderRadius: '0.5rem', 
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '1.5rem' 
      }}>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
            WebAuthn認証器を読み込み中...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ 
      backgroundColor: 'white', 
      borderRadius: '0.5rem', 
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
      padding: '1.5rem' 
    }}>
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        marginBottom: '1.5rem' 
      }}>
        <FingerPrintIcon style={{ 
          width: '1.5rem', 
          height: '1.5rem', 
          color: 'var(--color-primary-600)', 
          marginRight: '0.75rem' 
        }} />
        <h3 style={{ 
          fontSize: '1.125rem', 
          fontWeight: 500, 
          color: '#1f2937',
          margin: 0
        }}>
          WebAuthn認証器
        </h3>
      </div>

      {error && (
        <div className="error-message" style={{ marginBottom: '1.5rem' }}>
          {error}
        </div>
      )}

      {/* 新しい認証器の登録 */}
      {user && (
        <div style={{ marginBottom: '2rem' }}>
          <h4 style={{ 
            fontSize: '1rem', 
            fontWeight: 500, 
            color: '#1f2937',
            marginBottom: '0.75rem'
          }}>
            新しい認証器を追加
          </h4>
          <WebAuthnRegisterButton
            userId={user.id}
            username={user.username}
            displayName={user.username}
            onSuccess={handleCredentialRegistered}
            onError={handleRegistrationError}
          />
        </div>
      )}

      {/* 既存の認証器一覧 */}
      <div>
        <h4 style={{ 
          fontSize: '1rem', 
          fontWeight: 500, 
          color: '#1f2937',
          marginBottom: '1rem'
        }}>
          登録済み認証器
        </h4>

        {credentials.length === 0 ? (
          <div style={{ 
            textAlign: 'center', 
            padding: '2rem',
            color: '#6b7280'
          }}>
            <FingerPrintIcon style={{ 
              width: '3rem', 
              height: '3rem', 
              margin: '0 auto 0.5rem',
              color: '#d1d5db'
            }} />
            <p style={{ margin: 0 }}>WebAuthn認証器が登録されていません</p>
            <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.875rem' }}>
              指紋認証やセキュリティキーを追加してパスワードレス認証を有効にできます
            </p>
          </div>
        ) : (
          <div style={{ 
            display: 'grid', 
            gap: '1rem', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' 
          }}>
            {credentials.map((credential) => (
              <div
                key={credential.id}
                style={{
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.5rem',
                  padding: '1rem',
                  transition: 'box-shadow 0.2s'
                }}
                onMouseOver={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = '0 10px 15px -3px rgba(0, 0, 0, 0.1)';
                }}
                onMouseOut={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = 'none';
                }}
              >
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  marginBottom: '0.75rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span style={{ fontSize: '1.5rem', marginRight: '0.5rem' }}>
                      {WebAuthnService.getAuthenticatorIcon(credential)}
                    </span>
                    {editingCredential === credential.id ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <input
                          type="text"
                          value={editingName}
                          onChange={(e) => setEditingName(e.target.value)}
                          style={{
                            padding: '0.25rem 0.5rem',
                            border: '1px solid #d1d5db',
                            borderRadius: '0.25rem',
                            fontSize: '0.875rem'
                          }}
                          maxLength={100}
                        />
                        <button
                          onClick={() => saveCredentialName(credential.id)}
                          style={{
                            padding: '0.25rem',
                            backgroundColor: '#10b981',
                            color: 'white',
                            border: 'none',
                            borderRadius: '0.25rem',
                            cursor: 'pointer'
                          }}
                        >
                          <CheckIcon style={{ width: '1rem', height: '1rem' }} />
                        </button>
                        <button
                          onClick={cancelEditingCredential}
                          style={{
                            padding: '0.25rem',
                            backgroundColor: '#6b7280',
                            color: 'white',
                            border: 'none',
                            borderRadius: '0.25rem',
                            cursor: 'pointer'
                          }}
                        >
                          <XMarkIcon style={{ width: '1rem', height: '1rem' }} />
                        </button>
                      </div>
                    ) : (
                      <h5 style={{ 
                        fontSize: '0.875rem', 
                        fontWeight: 500, 
                        color: '#1f2937',
                        margin: 0
                      }}>
                        {credential.name}
                      </h5>
                    )}
                  </div>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: '0.25rem 0.625rem',
                    borderRadius: '9999px',
                    fontSize: '0.75rem',
                    fontWeight: 500,
                    backgroundColor: '#dcfce7',
                    color: '#166534'
                  }}>
                    <ShieldCheckIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                    有効
                  </span>
                </div>
                
                <div style={{ 
                  fontSize: '0.75rem', 
                  color: '#6b7280',
                  marginBottom: '0.75rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem'
                }}>
                  <div>
                    <span style={{ fontWeight: 500 }}>種類:</span>
                    <span style={{ marginLeft: '0.25rem' }}>
                      {WebAuthnService.getAuthenticatorType(credential)}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                    <span style={{ fontWeight: 500 }}>登録日:</span>
                    <span style={{ marginLeft: '0.25rem' }}>{formatDate(credential.created_at)}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                    <span style={{ fontWeight: 500 }}>最終使用:</span>
                    <span style={{ marginLeft: '0.25rem' }}>{formatLastUsed(credential.last_used_at)}</span>
                  </div>
                  <div>
                    <span style={{ fontWeight: 500 }}>使用回数:</span>
                    <span style={{ marginLeft: '0.25rem' }}>{credential.sign_count}回</span>
                  </div>
                </div>
                
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                  {editingCredential !== credential.id && (
                    <button
                      onClick={() => startEditingCredential(credential)}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        padding: '0.25rem 0.75rem',
                        border: 'none',
                        fontSize: '0.875rem',
                        fontWeight: 500,
                        borderRadius: '0.375rem',
                        color: '#1f2937',
                        backgroundColor: '#f3f4f6',
                        cursor: 'pointer',
                        transition: 'background-color 0.2s'
                      }}
                      onMouseOver={(e) => {
                        (e.currentTarget as HTMLElement).style.backgroundColor = '#e5e7eb';
                      }}
                      onMouseOut={(e) => {
                        (e.currentTarget as HTMLElement).style.backgroundColor = '#f3f4f6';
                      }}
                    >
                      <PencilIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                      名前を編集
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteCredential(credential.id)}
                    disabled={editingCredential === credential.id}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '0.25rem 0.75rem',
                      border: 'none',
                      fontSize: '0.875rem',
                      fontWeight: 500,
                      borderRadius: '0.375rem',
                      color: '#b91c1c',
                      backgroundColor: '#fef2f2',
                      cursor: editingCredential === credential.id ? 'not-allowed' : 'pointer',
                      opacity: editingCredential === credential.id ? 0.5 : 1,
                      transition: 'background-color 0.2s'
                    }}
                    onMouseOver={(e) => {
                      if (editingCredential !== credential.id) {
                        (e.currentTarget as HTMLElement).style.backgroundColor = '#fecaca';
                      }
                    }}
                    onMouseOut={(e) => {
                      if (editingCredential !== credential.id) {
                        (e.currentTarget as HTMLElement).style.backgroundColor = '#fef2f2';
                      }
                    }}
                  >
                    <TrashIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                    削除
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default WebAuthnCredentialsSection;