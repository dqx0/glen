import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLocation, useNavigate } from 'react-router-dom';
import { OAuth2Service } from '../services/oauth2Service';
import type { OAuth2Client, AuthorizeRequest } from '../services/oauth2Service';
import { getErrorMessage } from '../utils/errorUtils';
import { 
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';

interface AuthorizeParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

const OAuth2Authorize: React.FC = () => {
  const { user, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  
  const [client, setClient] = useState<OAuth2Client | null>(null);
  const [params, setParams] = useState<AuthorizeParams | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [authorizing, setAuthorizing] = useState(false);
  const [requestedScopes, setRequestedScopes] = useState<string[]>([]);

  const scopeDescriptions: { [key: string]: string } = {
    read: 'プロフィール情報の読み取り',
    write: 'プロフィール情報の更新',
    profile: '基本プロフィール情報へのアクセス',
    email: 'メールアドレスへのアクセス'
  };

  useEffect(() => {
    const urlParams = new URLSearchParams(location.search);
    
    // OAuth2パラメータを抽出
    const authParams: AuthorizeParams = {
      client_id: urlParams.get('client_id') || '',
      redirect_uri: urlParams.get('redirect_uri') || '',
      response_type: urlParams.get('response_type') || '',
      scope: urlParams.get('scope') || '',
      state: urlParams.get('state') || undefined,
      code_challenge: urlParams.get('code_challenge') || undefined,
      code_challenge_method: urlParams.get('code_challenge_method') || undefined,
    };

    // 必須パラメータの検証
    if (!authParams.client_id || !authParams.redirect_uri || !authParams.response_type) {
      setError('必須パラメータが不足しています');
      setLoading(false);
      return;
    }

    if (authParams.response_type !== 'code') {
      setError('サポートされていないresponse_typeです');
      setLoading(false);
      return;
    }

    setParams(authParams);
    setRequestedScopes(authParams.scope.split(' ').filter(s => s.trim() !== ''));

    // ユーザーが認証されていない場合はログインページにリダイレクト
    if (!isAuthenticated) {
      const loginUrl = `/login?redirect_uri=${encodeURIComponent(location.pathname + location.search)}`;
      navigate(loginUrl);
      return;
    }

    // クライアント情報を取得
    loadClient(authParams.client_id);
  }, [location, isAuthenticated, navigate]);

  const loadClient = async (clientId: string) => {
    try {
      setLoading(true);
      setError(null);

      const clientData = await OAuth2Service.getClient(clientId);
      setClient(clientData);

      // リダイレクトURIの検証
      if (params && !clientData.redirect_uris.includes(params.redirect_uri)) {
        throw new Error('無効なリダイレクトURIです');
      }

      // スコープの検証
      const invalidScopes = requestedScopes.filter(scope => !clientData.scopes.includes(scope));
      if (invalidScopes.length > 0) {
        throw new Error(`無効なスコープが含まれています: ${invalidScopes.join(', ')}`);
      }

    } catch (error: unknown) {
      console.error('Failed to load OAuth2 client:', error);
      setError(getErrorMessage(error, 'クライアント情報の取得に失敗しました'));
    } finally {
      setLoading(false);
    }
  };

  const handleAuthorize = async () => {
    if (!params || !client || !user) return;

    try {
      setAuthorizing(true);
      setError(null);

      const authorizeRequest: AuthorizeRequest = {
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        response_type: params.response_type,
        scope: params.scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
      };

      await OAuth2Service.authorize(authorizeRequest);

      // 成功時は認可コードとともにリダイレクト
      // 実際のフローでは、サーバーが直接リダイレクトするため、ここには到達しない
      
    } catch (error: unknown) {
      console.error('Authorization failed:', error);
      setError(getErrorMessage(error, '認可に失敗しました'));
    } finally {
      setAuthorizing(false);
    }
  };

  const handleDeny = () => {
    if (!params) return;

    // 拒否時のリダイレクト
    const redirectUrl = new URL(params.redirect_uri);
    redirectUrl.searchParams.set('error', 'access_denied');
    redirectUrl.searchParams.set('error_description', 'The user denied the request');
    if (params.state) {
      redirectUrl.searchParams.set('state', params.state);
    }

    window.location.href = redirectUrl.toString();
  };

  if (loading) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center',
        backgroundColor: '#f9fafb'
      }}>
        <div style={{ fontSize: '1.125rem', color: '#6b7280' }}>
          認可情報を確認しています...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center',
        backgroundColor: '#f9fafb',
        padding: '1rem'
      }}>
        <div style={{
          backgroundColor: 'white',
          borderRadius: '0.5rem',
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
          padding: '2rem',
          maxWidth: '28rem',
          width: '100%',
          textAlign: 'center'
        }}>
          <ExclamationTriangleIcon style={{
            width: '3rem',
            height: '3rem',
            color: '#dc2626',
            margin: '0 auto 1rem'
          }} />
          <h2 style={{
            fontSize: '1.125rem',
            fontWeight: 500,
            color: '#1f2937',
            marginBottom: '0.5rem'
          }}>
            認可エラー
          </h2>
          <p style={{
            fontSize: '0.875rem',
            color: '#6b7280',
            marginBottom: '1.5rem'
          }}>
            {error}
          </p>
          <button
            onClick={() => navigate('/dashboard')}
            className="btn-primary"
          >
            ダッシュボードに戻る
          </button>
        </div>
      </div>
    );
  }

  if (!client || !params) return null;

  return (
    <div style={{ 
      minHeight: '100vh', 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'center',
      backgroundColor: '#f9fafb',
      padding: '1rem'
    }}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '0.5rem',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '2rem',
        maxWidth: '28rem',
        width: '100%'
      }}>
        <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
          <ShieldCheckIcon style={{
            width: '3rem',
            height: '3rem',
            color: 'var(--color-primary-600)',
            margin: '0 auto 1rem'
          }} />
          <h1 style={{
            fontSize: '1.25rem',
            fontWeight: 600,
            color: '#1f2937',
            marginBottom: '0.5rem'
          }}>
            アプリケーションの認可
          </h1>
          <p style={{
            fontSize: '0.875rem',
            color: '#6b7280'
          }}>
            {user?.username}としてログイン中
          </p>
        </div>

        <div style={{
          border: '1px solid #e5e7eb',
          borderRadius: '0.5rem',
          padding: '1.5rem',
          marginBottom: '1.5rem',
          backgroundColor: '#f9fafb'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{
              width: '2.5rem',
              height: '2.5rem',
              borderRadius: '0.375rem',
              backgroundColor: 'var(--color-primary-100)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: '0.75rem'
            }}>
              <span style={{
                fontSize: '1rem',
                fontWeight: 600,
                color: 'var(--color-primary-600)'
              }}>
                {client.name.charAt(0).toUpperCase()}
              </span>
            </div>
            <div>
              <h3 style={{
                fontSize: '1rem',
                fontWeight: 500,
                color: '#1f2937',
                margin: 0
              }}>
                {client.name}
              </h3>
              {client.description && (
                <p style={{
                  fontSize: '0.875rem',
                  color: '#6b7280',
                  margin: '0.25rem 0 0 0'
                }}>
                  {client.description}
                </p>
              )}
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
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
              {client.is_public ? 'Public Client' : 'Confidential Client'}
            </span>
          </div>

          <div>
            <p style={{
              fontSize: '0.875rem',
              fontWeight: 500,
              color: '#1f2937',
              marginBottom: '0.5rem'
            }}>
              このアプリケーションは以下の権限を要求しています：
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {requestedScopes.map((scope) => (
                <div key={scope} style={{ display: 'flex', alignItems: 'center' }}>
                  <CheckIcon style={{
                    width: '1rem',
                    height: '1rem',
                    color: '#059669',
                    marginRight: '0.5rem'
                  }} />
                  <span style={{ fontSize: '0.875rem', color: '#374151' }}>
                    <strong>{scope}</strong>: {scopeDescriptions[scope] || 'カスタムスコープ'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{
          padding: '1rem',
          backgroundColor: '#fef3c7',
          borderRadius: '0.5rem',
          marginBottom: '1.5rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start' }}>
            <ExclamationTriangleIcon style={{
              width: '1.25rem',
              height: '1.25rem',
              color: '#f59e0b',
              marginRight: '0.5rem',
              flexShrink: 0,
              marginTop: '0.125rem'
            }} />
            <div>
              <p style={{
                fontSize: '0.875rem',
                color: '#92400e',
                margin: 0
              }}>
                認可することで、このアプリケーションがあなたのGlen IDアカウントの指定された情報にアクセスできるようになります。
                信頼できるアプリケーションのみ認可してください。
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="error-message" style={{ marginBottom: '1.5rem' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={handleDeny}
            disabled={authorizing}
            style={{
              flex: 1,
              padding: '0.75rem 1rem',
              border: '1px solid #d1d5db',
              borderRadius: '0.375rem',
              backgroundColor: 'white',
              color: '#374151',
              cursor: authorizing ? 'not-allowed' : 'pointer',
              opacity: authorizing ? 0.5 : 1,
              fontSize: '0.875rem',
              fontWeight: 500,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <XMarkIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
            拒否
          </button>
          <button
            onClick={handleAuthorize}
            disabled={authorizing}
            style={{
              flex: 1,
              padding: '0.75rem 1rem',
              border: 'none',
              borderRadius: '0.375rem',
              backgroundColor: 'var(--color-primary-600)',
              color: 'white',
              cursor: authorizing ? 'not-allowed' : 'pointer',
              opacity: authorizing ? 0.5 : 1,
              fontSize: '0.875rem',
              fontWeight: 500,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <CheckIcon style={{ width: '1rem', height: '1rem', marginRight: '0.5rem' }} />
            {authorizing ? '認可中...' : '認可する'}
          </button>
        </div>

        <div style={{
          textAlign: 'center',
          marginTop: '1.5rem',
          fontSize: '0.75rem',
          color: '#6b7280'
        }}>
          <p style={{ margin: 0 }}>
            認可後、{params.redirect_uri} にリダイレクトされます
          </p>
        </div>
      </div>
    </div>
  );
};

export default OAuth2Authorize;