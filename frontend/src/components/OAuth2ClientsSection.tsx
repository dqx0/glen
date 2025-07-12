import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { OAuth2Service } from '../services/oauth2Service';
import type { OAuth2Client, CreateClientRequest } from '../services/oauth2Service';
import { getErrorMessage } from '../utils/errorUtils';
import { 
  CogIcon,
  PlusIcon,
  TrashIcon,
  KeyIcon,
  EyeIcon,
  EyeSlashIcon,
  ClipboardDocumentIcon,
  XMarkIcon,
  CheckIcon
} from '@heroicons/react/24/outline';


const OAuth2ClientsSection: React.FC = () => {
  const { user } = useAuth();
  const [clients, setClients] = useState<OAuth2Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newClient, setNewClient] = useState<OAuth2Client | null>(null);
  const [showSecret, setShowSecret] = useState<{ [key: string]: boolean }>({});
  const [copied, setCopied] = useState<{ [key: string]: boolean }>({});

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    redirect_uris: [''],
    scopes: ['read'],
    is_public: false
  });

  const availableScopes = ['read', 'write', 'profile', 'email'];

  useEffect(() => {
    if (user) {
      loadClients();
    }
  }, [user]);

  const loadClients = async () => {
    if (!user?.id) return;

    try {
      setLoading(true);
      setError(null);
      
      const data = await OAuth2Service.getClients(user.id);
      setClients(data);
    } catch (error: unknown) {
      console.error('Failed to load OAuth2 clients:', error);
      setError(getErrorMessage(error, 'OAuth2クライアントの読み込みに失敗しました'));
      setClients([]);
    } finally {
      setLoading(false);
    }
  };

  const createClient = async () => {
    if (!user?.id || !formData.name.trim()) return;

    // Validation
    const validRedirectUris = formData.redirect_uris.filter(uri => uri.trim() !== '');
    if (validRedirectUris.length === 0) {
      setError('リダイレクトURIを少なくとも1つ入力してください');
      return;
    }

    if (formData.scopes.length === 0) {
      setError('スコープを少なくとも1つ選択してください');
      return;
    }

    try {
      setCreating(true);
      setError(null);

      const requestData: CreateClientRequest = {
        user_id: user.id,
        name: formData.name.trim(),
        description: formData.description.trim(),
        redirect_uris: validRedirectUris,
        scopes: formData.scopes,
        is_public: formData.is_public
      };

      const newClientData = await OAuth2Service.createClient(requestData);
      setNewClient(newClientData);
      setShowCreateModal(false);
      resetForm();
      await loadClients();
    } catch (error: unknown) {
      console.error('Failed to create OAuth2 client:', error);
      setError(getErrorMessage(error, 'OAuth2クライアントの作成に失敗しました'));
    } finally {
      setCreating(false);
    }
  };

  const deleteClient = async (clientId: string) => {
    if (!user?.id || !confirm('このクライアントを削除しますか？この操作は取り消せません。')) return;

    try {
      await OAuth2Service.deleteClient(clientId);
      await loadClients();
    } catch (error: unknown) {
      console.error('Failed to delete OAuth2 client:', error);
      setError(getErrorMessage(error, 'OAuth2クライアントの削除に失敗しました'));
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      redirect_uris: [''],
      scopes: ['read'],
      is_public: false
    });
  };

  const addRedirectUri = () => {
    setFormData(prev => ({
      ...prev,
      redirect_uris: [...prev.redirect_uris, '']
    }));
  };

  const removeRedirectUri = (index: number) => {
    setFormData(prev => ({
      ...prev,
      redirect_uris: prev.redirect_uris.filter((_, i) => i !== index)
    }));
  };

  const updateRedirectUri = (index: number, value: string) => {
    setFormData(prev => ({
      ...prev,
      redirect_uris: prev.redirect_uris.map((uri, i) => i === index ? value : uri)
    }));
  };

  const toggleScope = (scope: string) => {
    setFormData(prev => ({
      ...prev,
      scopes: prev.scopes.includes(scope)
        ? prev.scopes.filter(s => s !== scope)
        : [...prev.scopes, scope]
    }));
  };

  const toggleSecret = (clientId: string) => {
    setShowSecret(prev => ({
      ...prev,
      [clientId]: !prev[clientId]
    }));
  };

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(prev => ({ ...prev, [key]: true }));
      setTimeout(() => {
        setCopied(prev => ({ ...prev, [key]: false }));
      }, 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('ja-JP');
  };

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
        justifyContent: 'space-between',
        marginBottom: '1.5rem' 
      }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <CogIcon style={{ 
            width: '1.5rem', 
            height: '1.5rem', 
            color: 'var(--color-primary-600)', 
            marginRight: '0.75rem' 
          }} />
          <div>
            <h3 style={{ 
              fontSize: '1.125rem', 
              fontWeight: 500, 
              color: '#1f2937',
              margin: 0
            }}>
              OAuth2クライアント管理
            </h3>
            <p style={{ 
              fontSize: '0.875rem', 
              color: '#6b7280',
              margin: '0.25rem 0 0 0'
            }}>
              他のアプリケーションからGlen IDにアクセスするためのクライアントを管理
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
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
            cursor: 'pointer',
            transition: 'background-color 0.2s'
          }}
          onMouseOver={(e) => {
            (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-700)';
          }}
          onMouseOut={(e) => {
            (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--color-primary-600)';
          }}
        >
          <PlusIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
          新しいクライアントを作成
        </button>
      </div>

      {error && (
        <div className="error-message" style={{ marginBottom: '1.5rem' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>読み込み中...</div>
        </div>
      ) : clients.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <CogIcon style={{ 
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
            OAuth2クライアントがありません
          </h3>
          <p style={{ 
            fontSize: '0.875rem', 
            color: '#6b7280',
            margin: 0
          }}>
            新しいクライアントを作成して他のアプリケーションと連携しましょう
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '1rem' }}>
          {clients.map((client) => (
            <div
              key={client.id}
              style={{
                border: '1px solid #e5e7eb',
                borderRadius: '0.5rem',
                padding: '1.5rem',
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
                alignItems: 'flex-start', 
                justifyContent: 'space-between',
                marginBottom: '1rem'
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <h4 style={{ 
                      fontSize: '1rem', 
                      fontWeight: 500, 
                      color: '#1f2937',
                      margin: 0
                    }}>
                      {client.name}
                    </h4>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '0.25rem 0.625rem',
                      borderRadius: '9999px',
                      fontSize: '0.75rem',
                      fontWeight: 500,
                      backgroundColor: client.is_public ? '#dbeafe' : '#f3e8ff',
                      color: client.is_public ? '#1d4ed8' : '#7c3aed'
                    }}>
                      {client.is_public ? 'Public' : 'Confidential'}
                    </span>
                    {!client.is_active && (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        padding: '0.25rem 0.625rem',
                        borderRadius: '9999px',
                        fontSize: '0.75rem',
                        fontWeight: 500,
                        backgroundColor: '#fef2f2',
                        color: '#b91c1c'
                      }}>
                        無効
                      </span>
                    )}
                  </div>
                  {client.description && (
                    <p style={{ 
                      fontSize: '0.875rem', 
                      color: '#6b7280',
                      margin: '0 0 0.5rem 0'
                    }}>
                      {client.description}
                    </p>
                  )}
                  <div style={{ 
                    fontSize: '0.75rem', 
                    color: '#6b7280',
                    marginBottom: '0.5rem'
                  }}>
                    作成日: {formatDate(client.created_at)}
                  </div>
                </div>
                <button
                  onClick={() => deleteClient(client.id)}
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
                  削除
                </button>
              </div>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {/* Client ID */}
                <div>
                  <label style={{ 
                    fontSize: '0.75rem', 
                    fontWeight: 500, 
                    color: '#6b7280',
                    marginBottom: '0.25rem',
                    display: 'block'
                  }}>
                    Client ID
                  </label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <code style={{ 
                      fontSize: '0.875rem', 
                      fontFamily: 'monospace', 
                      color: '#1f2937',
                      backgroundColor: '#f3f4f6',
                      padding: '0.25rem 0.5rem',
                      borderRadius: '0.25rem',
                      flex: 1,
                      wordBreak: 'break-all'
                    }}>
                      {client.client_id}
                    </code>
                    <button
                      onClick={() => copyToClipboard(client.client_id, `client_id_${client.id}`)}
                      style={{
                        padding: '0.25rem',
                        border: 'none',
                        borderRadius: '0.25rem',
                        backgroundColor: '#f3f4f6',
                        cursor: 'pointer',
                        color: copied[`client_id_${client.id}`] ? '#059669' : '#6b7280'
                      }}
                    >
                      {copied[`client_id_${client.id}`] ? (
                        <CheckIcon style={{ width: '1rem', height: '1rem' }} />
                      ) : (
                        <ClipboardDocumentIcon style={{ width: '1rem', height: '1rem' }} />
                      )}
                    </button>
                  </div>
                </div>

                {/* Client Secret (for confidential clients) */}
                {!client.is_public && client.client_secret && (
                  <div>
                    <label style={{ 
                      fontSize: '0.75rem', 
                      fontWeight: 500, 
                      color: '#6b7280',
                      marginBottom: '0.25rem',
                      display: 'block'
                    }}>
                      Client Secret
                    </label>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <code style={{ 
                        fontSize: '0.875rem', 
                        fontFamily: 'monospace', 
                        color: '#1f2937',
                        backgroundColor: '#f3f4f6',
                        padding: '0.25rem 0.5rem',
                        borderRadius: '0.25rem',
                        flex: 1,
                        wordBreak: 'break-all'
                      }}>
                        {showSecret[client.id] ? client.client_secret : '••••••••••••••••'}
                      </code>
                      <button
                        onClick={() => toggleSecret(client.id)}
                        style={{
                          padding: '0.25rem',
                          border: 'none',
                          borderRadius: '0.25rem',
                          backgroundColor: '#f3f4f6',
                          cursor: 'pointer',
                          color: '#6b7280'
                        }}
                      >
                        {showSecret[client.id] ? (
                          <EyeSlashIcon style={{ width: '1rem', height: '1rem' }} />
                        ) : (
                          <EyeIcon style={{ width: '1rem', height: '1rem' }} />
                        )}
                      </button>
                      {showSecret[client.id] && (
                        <button
                          onClick={() => copyToClipboard(client.client_secret!, `client_secret_${client.id}`)}
                          style={{
                            padding: '0.25rem',
                            border: 'none',
                            borderRadius: '0.25rem',
                            backgroundColor: '#f3f4f6',
                            cursor: 'pointer',
                            color: copied[`client_secret_${client.id}`] ? '#059669' : '#6b7280'
                          }}
                        >
                          {copied[`client_secret_${client.id}`] ? (
                            <CheckIcon style={{ width: '1rem', height: '1rem' }} />
                          ) : (
                            <ClipboardDocumentIcon style={{ width: '1rem', height: '1rem' }} />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                )}

                {/* Redirect URIs */}
                <div>
                  <label style={{ 
                    fontSize: '0.75rem', 
                    fontWeight: 500, 
                    color: '#6b7280',
                    marginBottom: '0.25rem',
                    display: 'block'
                  }}>
                    リダイレクトURI
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    {client.redirect_uris.map((uri, index) => (
                      <code key={index} style={{ 
                        fontSize: '0.875rem', 
                        fontFamily: 'monospace', 
                        color: '#1f2937',
                        backgroundColor: '#f3f4f6',
                        padding: '0.25rem 0.5rem',
                        borderRadius: '0.25rem',
                        wordBreak: 'break-all'
                      }}>
                        {uri}
                      </code>
                    ))}
                  </div>
                </div>

                {/* Scopes */}
                <div>
                  <label style={{ 
                    fontSize: '0.75rem', 
                    fontWeight: 500, 
                    color: '#6b7280',
                    marginBottom: '0.25rem',
                    display: 'block'
                  }}>
                    スコープ
                  </label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                    {client.scopes.map((scope) => (
                      <span
                        key={scope}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          padding: '0.25rem 0.625rem',
                          borderRadius: '9999px',
                          fontSize: '0.75rem',
                          fontWeight: 500,
                          backgroundColor: '#eff6ff',
                          color: '#1d4ed8'
                        }}
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Client Modal */}
      {showCreateModal && (
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
            maxWidth: '32rem', 
            width: '100%',
            maxHeight: '90vh',
            overflow: 'auto'
          }}>
            <div style={{ padding: '1.5rem' }}>
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'space-between',
                marginBottom: '1.5rem'
              }}>
                <h3 style={{ 
                  fontSize: '1.125rem', 
                  fontWeight: 500, 
                  color: '#1f2937',
                  margin: 0
                }}>
                  新しいOAuth2クライアントを作成
                </h3>
                <button
                  onClick={() => setShowCreateModal(false)}
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

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {/* Name */}
                <div>
                  <label style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#374151',
                    marginBottom: '0.5rem',
                    display: 'block'
                  }}>
                    アプリケーション名 *
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="例：My App"
                    className="form-input"
                  />
                </div>

                {/* Description */}
                <div>
                  <label style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#374151',
                    marginBottom: '0.5rem',
                    display: 'block'
                  }}>
                    説明
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="アプリケーションの説明"
                    rows={3}
                    className="form-input"
                  />
                </div>

                {/* Client Type */}
                <div>
                  <label style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#374151',
                    marginBottom: '0.5rem',
                    display: 'block'
                  }}>
                    クライアントタイプ
                  </label>
                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        checked={!formData.is_public}
                        onChange={() => setFormData(prev => ({ ...prev, is_public: false }))}
                        style={{ marginRight: '0.5rem' }}
                      />
                      <span style={{ fontSize: '0.875rem' }}>Confidential (サーバーサイド)</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        checked={formData.is_public}
                        onChange={() => setFormData(prev => ({ ...prev, is_public: true }))}
                        style={{ marginRight: '0.5rem' }}
                      />
                      <span style={{ fontSize: '0.875rem' }}>Public (SPA/モバイル)</span>
                    </label>
                  </div>
                </div>

                {/* Redirect URIs */}
                <div>
                  <label style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#374151',
                    marginBottom: '0.5rem',
                    display: 'block'
                  }}>
                    リダイレクトURI *
                  </label>
                  {formData.redirect_uris.map((uri, index) => (
                    <div key={index} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                      <input
                        type="url"
                        value={uri}
                        onChange={(e) => updateRedirectUri(index, e.target.value)}
                        placeholder="https://example.com/auth/callback"
                        className="form-input"
                        style={{ flex: 1 }}
                      />
                      {formData.redirect_uris.length > 1 && (
                        <button
                          onClick={() => removeRedirectUri(index)}
                          style={{
                            padding: '0.5rem',
                            border: 'none',
                            borderRadius: '0.375rem',
                            backgroundColor: '#fef2f2',
                            color: '#b91c1c',
                            cursor: 'pointer'
                          }}
                        >
                          <TrashIcon style={{ width: '1rem', height: '1rem' }} />
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    onClick={addRedirectUri}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '0.25rem 0.5rem',
                      border: '1px dashed #d1d5db',
                      borderRadius: '0.375rem',
                      backgroundColor: 'transparent',
                      color: '#6b7280',
                      cursor: 'pointer',
                      fontSize: '0.875rem'
                    }}
                  >
                    <PlusIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                    URIを追加
                  </button>
                </div>

                {/* Scopes */}
                <div>
                  <label style={{ 
                    fontSize: '0.875rem', 
                    fontWeight: 500, 
                    color: '#374151',
                    marginBottom: '0.5rem',
                    display: 'block'
                  }}>
                    スコープ *
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem' }}>
                    {availableScopes.map((scope) => (
                      <label key={scope} style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={formData.scopes.includes(scope)}
                          onChange={() => toggleScope(scope)}
                          style={{ marginRight: '0.5rem' }}
                        />
                        <span style={{ fontSize: '0.875rem' }}>{scope}</span>
                      </label>
                    ))}
                  </div>
                </div>

                {error && (
                  <div className="error-message">
                    {error}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
                  <button
                    onClick={() => setShowCreateModal(false)}
                    style={{
                      padding: '0.5rem 1rem',
                      border: '1px solid #d1d5db',
                      borderRadius: '0.375rem',
                      backgroundColor: 'white',
                      color: '#374151',
                      cursor: 'pointer',
                      fontSize: '0.875rem'
                    }}
                  >
                    キャンセル
                  </button>
                  <button
                    onClick={createClient}
                    disabled={creating || !formData.name.trim()}
                    style={{
                      padding: '0.5rem 1rem',
                      border: 'none',
                      borderRadius: '0.375rem',
                      backgroundColor: 'var(--color-primary-600)',
                      color: 'white',
                      cursor: creating || !formData.name.trim() ? 'not-allowed' : 'pointer',
                      opacity: creating || !formData.name.trim() ? 0.5 : 1,
                      fontSize: '0.875rem'
                    }}
                  >
                    {creating ? '作成中...' : 'クライアントを作成'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* New Client Success Modal */}
      {newClient && (
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
            maxWidth: '32rem', 
            width: '100%'
          }}>
            <div style={{ padding: '1.5rem' }}>
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
                  OAuth2クライアントが作成されました
                </h3>
                <button
                  onClick={() => setNewClient(null)}
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
                以下の認証情報を安全な場所に保存してください。{!newClient.is_public && 'Client Secretは再度表示することはできません。'}
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <label style={{ 
                    fontSize: '0.75rem', 
                    fontWeight: 500, 
                    color: '#6b7280',
                    marginBottom: '0.25rem',
                    display: 'block'
                  }}>
                    Client ID
                  </label>
                  <div style={{ 
                    backgroundColor: '#f3f4f6', 
                    borderRadius: '0.5rem', 
                    padding: '0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}>
                    <code style={{ 
                      fontSize: '0.875rem', 
                      fontFamily: 'monospace', 
                      color: '#1f2937',
                      wordBreak: 'break-all',
                      flex: 1
                    }}>
                      {newClient.client_id}
                    </code>
                    <button
                      onClick={() => copyToClipboard(newClient.client_id, 'new_client_id')}
                      style={{
                        padding: '0.25rem',
                        border: 'none',
                        borderRadius: '0.25rem',
                        backgroundColor: 'white',
                        cursor: 'pointer',
                        color: copied.new_client_id ? '#059669' : '#6b7280'
                      }}
                    >
                      {copied.new_client_id ? (
                        <CheckIcon style={{ width: '1rem', height: '1rem' }} />
                      ) : (
                        <ClipboardDocumentIcon style={{ width: '1rem', height: '1rem' }} />
                      )}
                    </button>
                  </div>
                </div>

                {!newClient.is_public && newClient.client_secret && (
                  <div>
                    <label style={{ 
                      fontSize: '0.75rem', 
                      fontWeight: 500, 
                      color: '#6b7280',
                      marginBottom: '0.25rem',
                      display: 'block'
                    }}>
                      Client Secret
                    </label>
                    <div style={{ 
                      backgroundColor: '#f3f4f6', 
                      borderRadius: '0.5rem', 
                      padding: '0.75rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}>
                      <code style={{ 
                        fontSize: '0.875rem', 
                        fontFamily: 'monospace', 
                        color: '#1f2937',
                        wordBreak: 'break-all',
                        flex: 1
                      }}>
                        {newClient.client_secret}
                      </code>
                      <button
                        onClick={() => copyToClipboard(newClient.client_secret!, 'new_client_secret')}
                        style={{
                          padding: '0.25rem',
                          border: 'none',
                          borderRadius: '0.25rem',
                          backgroundColor: 'white',
                          cursor: 'pointer',
                          color: copied.new_client_secret ? '#059669' : '#6b7280'
                        }}
                      >
                        {copied.new_client_secret ? (
                          <CheckIcon style={{ width: '1rem', height: '1rem' }} />
                        ) : (
                          <ClipboardDocumentIcon style={{ width: '1rem', height: '1rem' }} />
                        )}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <button
                onClick={() => setNewClient(null)}
                className="btn-primary"
                style={{ width: '100%', marginTop: '1.5rem' }}
              >
                完了
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OAuth2ClientsSection;