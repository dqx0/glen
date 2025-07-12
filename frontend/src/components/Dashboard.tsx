import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLocation } from 'react-router-dom';
import { AuthService } from '../services/authService';
import type { Token } from '../types/auth';
import SocialAccountsSection from './SocialAccountsSection';
import WebAuthnCredentialsSection from './WebAuthnCredentialsSection';
import OAuth2ClientsSection from './OAuth2ClientsSection';
import { getErrorMessage } from '../utils/errorUtils';
import { 
  KeyIcon, 
  TrashIcon, 
  PlusIcon,
  ArrowRightOnRectangleIcon,
  UserIcon,
  ClockIcon,
  TagIcon,
  XMarkIcon 
} from '@heroicons/react/24/outline';

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creatingApiKey, setCreatingApiKey] = useState(false);
  const [apiKeyName, setApiKeyName] = useState('');
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [socialLinkedKey, setSocialLinkedKey] = useState(0);

  useEffect(() => {
    console.log('Dashboard - useEffect, user:', user);
    if (user) {
      loadTokens();
    }
  }, [user]);

  useEffect(() => {
    // ソーシャルアカウント連携後のリフレッシュ
    const params = new URLSearchParams(location.search);
    if (params.get('social_linked') === 'true') {
      console.log('Social account linked, refreshing data');
      setSocialLinkedKey(prev => prev + 1);
      // URLパラメータをクリア
      window.history.replaceState({}, '', '/dashboard');
    }
  }, [location]);

  const loadTokens = async () => {
    if (!user || !user.id) {
      console.log('Dashboard - loadTokens: user or user.id is missing', { user });
      return;
    }

    try {
      setLoading(true);
      setError(null);
      console.log('Dashboard - loadTokens: calling AuthService.listTokens with user.id:', user.id);
      const userTokens = await AuthService.listTokens(user.id);
      
      // 安全な配列アクセス
      const safeTokens = Array.isArray(userTokens) ? userTokens : [];
      setTokens(safeTokens);
    } catch (error: unknown) {
      console.error('Failed to load tokens:', error);
      setError(getErrorMessage(error, 'トークンの読み込みに失敗しました'));
      // エラー時のフォールバック
      setTokens([]);
    } finally {
      setLoading(false);
    }
  };

  const createApiKey = async () => {
    if (!user || !user.id || !apiKeyName.trim()) return;

    try {
      setCreatingApiKey(true);
      const response = await AuthService.createAPIKey({
        user_id: user.id,
        name: apiKeyName.trim(),
        scopes: ['read', 'write'],
      });
      
      setNewApiKey(response.api_key);
      setApiKeyName('');
      await loadTokens();
    } catch (error: unknown) {
      console.error('Failed to create API key:', error);
      setError(getErrorMessage(error, 'APIキーの作成に失敗しました'));
    } finally {
      setCreatingApiKey(false);
    }
  };

  const revokeToken = async (tokenId: string) => {
    if (!user || !user.id) return;

    try {
      await AuthService.revokeToken({
        token_id: tokenId,
        user_id: user.id,
      });
      await loadTokens();
    } catch (error: unknown) {
      console.error('Failed to revoke token:', error);
      setError(getErrorMessage(error, 'トークンの無効化に失敗しました'));
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('ja-JP');
  };

  const closeApiKeyModal = () => {
    setNewApiKey(null);
  };

  if (!user) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center' 
      }}>
        <div style={{ fontSize: '1.125rem', color: '#6b7280' }}>
          ユーザー情報を読み込んでいます...
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f9fafb' }}>
      {/* Header */}
      <header style={{ 
        backgroundColor: 'white', 
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1)',
        borderBottom: '1px solid #e5e7eb'
      }}>
        <div style={{ 
          maxWidth: '1280px', 
          margin: '0 auto', 
          padding: '0 1rem' 
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center', 
            height: '4rem' 
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <UserIcon style={{ width: '2rem', height: '2rem', color: 'var(--color-primary-600)' }} />
              <h1 style={{ 
                fontSize: '1.25rem', 
                fontWeight: 600, 
                color: '#1f2937',
                margin: 0
              }}>
                Glen ID ダッシュボード
              </h1>
            </div>
            <button
              onClick={logout}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '0.5rem 1rem',
                border: 'none',
                fontSize: '0.875rem',
                fontWeight: 500,
                borderRadius: '0.375rem',
                color: '#374151',
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
              <ArrowRightOnRectangleIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
              ログアウト
            </button>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: '1280px', margin: '0 auto', padding: '1.5rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.5rem' }}>
          
          {/* User Info & Social Accounts Section */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
            gap: '1.5rem' 
          }}>
            {/* User Info Card */}
            <div style={{ 
              backgroundColor: 'white', 
              borderRadius: '0.5rem', 
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
              padding: '1.5rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1.5rem' }}>
                <UserIcon style={{ 
                  width: '2.5rem', 
                  height: '2.5rem', 
                  color: 'var(--color-primary-600)',
                  marginRight: '1rem'
                }} />
                <div>
                  <h3 style={{ 
                    fontSize: '1.125rem', 
                    fontWeight: 500, 
                    color: '#1f2937',
                    margin: 0
                  }}>
                    ユーザー情報
                  </h3>
                  <p style={{ 
                    fontSize: '0.875rem', 
                    color: '#6b7280',
                    margin: '0.25rem 0 0 0'
                  }}>
                    アカウントの詳細情報
                  </p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#6b7280' }}>ユーザー名</span>
                  <span style={{ fontSize: '0.875rem', color: '#1f2937' }}>{user.username}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#6b7280' }}>メールアドレス</span>
                  <span style={{ fontSize: '0.875rem', color: '#1f2937' }}>{user.email}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.875rem', fontWeight: 500, color: '#6b7280' }}>作成日</span>
                  <span style={{ fontSize: '0.875rem', color: '#1f2937' }}>{formatDate(user.created_at)}</span>
                </div>
              </div>
            </div>

            {/* Social Accounts Section */}
            <SocialAccountsSection key={socialLinkedKey} />
          </div>

          {/* WebAuthn Credentials Section */}
          <WebAuthnCredentialsSection />

          {/* OAuth2 Clients Section */}
          <OAuth2ClientsSection />

          {/* Token Management */}
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
              <KeyIcon style={{ 
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
                認証トークン管理
              </h3>
            </div>

            {/* API Key Creation */}
            <div style={{ 
              backgroundColor: '#f9fafb', 
              borderRadius: '0.5rem', 
              padding: '1rem',
              marginBottom: '1.5rem'
            }}>
              <h4 style={{ 
                fontSize: '1rem', 
                fontWeight: 500, 
                color: '#1f2937',
                marginBottom: '1rem'
              }}>
                新しいAPIキーを作成
              </h4>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <input
                    type="text"
                    placeholder="APIキー名（例：My App API）"
                    value={apiKeyName}
                    onChange={(e) => setApiKeyName(e.target.value)}
                    maxLength={100}
                    className="form-input"
                  />
                </div>
                <button
                  onClick={createApiKey}
                  disabled={!apiKeyName.trim() || creatingApiKey}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: '0.5rem 1rem',
                    border: 'none',
                    fontSize: '0.875rem',
                    fontWeight: 500,
                    borderRadius: '0.375rem',
                    color: 'white',
                    backgroundColor: 'var(--color-primary-600)',
                    cursor: creatingApiKey || !apiKeyName.trim() ? 'not-allowed' : 'pointer',
                    opacity: creatingApiKey || !apiKeyName.trim() ? 0.5 : 1,
                    transition: 'background-color 0.2s'
                  }}
                  onMouseOver={(e) => {
                    if (!creatingApiKey && apiKeyName.trim()) {
                      (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-700)';
                    }
                  }}
                  onMouseOut={(e) => {
                    if (!creatingApiKey && apiKeyName.trim()) {
                      (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-600)';
                    }
                  }}
                >
                  <PlusIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
                  {creatingApiKey ? '作成中...' : 'APIキーを作成'}
                </button>
              </div>
            </div>

            {error && (
              <div className="error-message" style={{ marginBottom: '1.5rem' }}>
                {error}
              </div>
            )}

            {/* Tokens List */}
            <div>
              <h4 style={{ 
                fontSize: '1rem', 
                fontWeight: 500, 
                color: '#1f2937',
                marginBottom: '1rem'
              }}>
                既存のトークン
              </h4>
              {loading ? (
                <div style={{ textAlign: 'center', padding: '2rem' }}>
                  <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>読み込み中...</div>
                </div>
              ) : tokens.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '2rem' }}>
                  <KeyIcon style={{ 
                    width: '3rem', 
                    height: '3rem', 
                    margin: '0 auto 0.5rem',
                    color: '#d1d5db'
                  }} />
                  <h3 style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#1f2937',
                    margin: '0.5rem 0 0.25rem 0'
                  }}>
                    トークンがありません
                  </h3>
                  <p style={{ 
                    fontSize: '0.875rem', 
                    color: '#6b7280',
                    margin: 0
                  }}>
                    新しいAPIキーを作成してください
                  </p>
                </div>
              ) : (
                <div style={{ 
                  display: 'grid', 
                  gap: '1rem', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' 
                }}>
                  {tokens.map((token) => (
                    <div
                      key={token.id}
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
                        <h5 style={{ 
                          fontSize: '0.875rem', 
                          fontWeight: 500, 
                          color: '#1f2937',
                          margin: 0
                        }}>
                          {token.name}
                        </h5>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '0.25rem 0.625rem',
                          borderRadius: '9999px',
                          fontSize: '0.75rem',
                          fontWeight: 500,
                          backgroundColor: token.token_type === 'api_key' ? '#dbeafe' : '#f3e8ff',
                          color: token.token_type === 'api_key' ? '#1d4ed8' : '#7c3aed'
                        }}>
                          {token.token_type === 'api_key' ? 'APIキー' : 'セッション'}
                        </span>
                      </div>
                      <div style={{ 
                        fontSize: '0.75rem', 
                        color: '#6b7280',
                        marginBottom: '0.75rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.5rem'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <TagIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                          <span style={{ fontWeight: 500 }}>スコープ:</span>
                          <span style={{ marginLeft: '0.25rem' }}>{token.scopes.join(', ')}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                          <span style={{ fontWeight: 500 }}>作成日:</span>
                          <span style={{ marginLeft: '0.25rem' }}>{formatDate(token.created_at)}</span>
                        </div>
                        {token.last_used_at && (
                          <div style={{ display: 'flex', alignItems: 'center' }}>
                            <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                            <span style={{ fontWeight: 500 }}>最終使用:</span>
                            <span style={{ marginLeft: '0.25rem' }}>{formatDate(token.last_used_at)}</span>
                          </div>
                        )}
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <button
                          onClick={() => revokeToken(token.id)}
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
                            cursor: 'pointer',
                            transition: 'background-color 0.2s'
                          }}
                          onMouseOver={(e) => {
                            (e.currentTarget as HTMLElement).style.backgroundColor = '#fecaca';
                          }}
                          onMouseOut={(e) => {
                            (e.currentTarget as HTMLElement).style.backgroundColor = '#fef2f2';
                          }}
                        >
                          <TrashIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                          無効化
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      {/* API Key Modal */}
      {newApiKey && (
        <div style={{ 
          position: 'fixed', 
          inset: 0, 
          backgroundColor: 'rgba(107, 114, 128, 0.5)', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center', 
          padding: '1rem',
          zIndex: 50
        }}>
          <div style={{ 
            backgroundColor: 'white', 
            borderRadius: '0.5rem', 
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
            maxWidth: '28rem', 
            width: '100%'
          }}>
            <div style={{ padding: '1.5rem 1.5rem 1rem' }}>
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'space-between',
                marginBottom: '1rem'
              }}>
                <h3 style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: 500, 
                  color: '#1f2937',
                  margin: 0
                }}>
                  APIキーが作成されました
                </h3>
                <button
                  onClick={closeApiKeyModal}
                  style={{
                    color: '#9ca3af',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer'
                  }}
                >
                  <XMarkIcon style={{ width: '1.5rem', height: '1.5rem' }} />
                </button>
              </div>
              <p style={{ 
                fontSize: '0.875rem', 
                color: '#6b7280',
                marginBottom: '1rem'
              }}>
                以下のAPIキーを安全な場所に保存してください。再度表示することはできません。
              </p>
              <div style={{ 
                backgroundColor: '#f3f4f6', 
                borderRadius: '0.5rem', 
                padding: '1rem',
                marginBottom: '1rem'
              }}>
                <code style={{ 
                  fontSize: '0.875rem', 
                  fontFamily: 'monospace', 
                  color: '#1f2937',
                  wordBreak: 'break-all'
                }}>
                  {newApiKey}
                </code>
              </div>
              <button
                onClick={closeApiKeyModal}
                className="btn-primary"
              >
                閉じる
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;