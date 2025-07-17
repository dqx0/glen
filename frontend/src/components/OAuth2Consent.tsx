import { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

interface ConsentParams {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state: string;
  code_challenge?: string;
  code_challenge_method?: string;
  user_id: string;
}

// 環境に応じたAPI GatewayのベースURLを取得
const getAPIGatewayBaseURL = (): string => {
  const env = process.env.NODE_ENV || 'development';
  if (env === 'production') {
    return 'https://api.glen.dqx0.com';
  }
  return 'http://localhost:8080';
};

const OAuth2Consent: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [params, setParams] = useState<ConsentParams | null>(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    // URLパラメータを解析
    const urlParams = new URLSearchParams(location.search);
    const consentParams: ConsentParams = {
      client_id: urlParams.get('client_id') || '',
      redirect_uri: urlParams.get('redirect_uri') || '',
      response_type: urlParams.get('response_type') || '',
      scope: urlParams.get('scope') || '',
      state: urlParams.get('state') || '',
      code_challenge: urlParams.get('code_challenge') || undefined,
      code_challenge_method: urlParams.get('code_challenge_method') || undefined,
      user_id: urlParams.get('user_id') || '',
    };

    // 必須パラメータの検証
    if (!consentParams.client_id || !consentParams.redirect_uri || !consentParams.response_type) {
      setError('必要なパラメータが不足しています');
      return;
    }

    setParams(consentParams);
  }, [location.search]);

  const handleConsent = async (approve: boolean) => {
    if (!params) {
      console.error('No params available');
      return;
    }

    console.log('handleConsent called with approve:', approve);
    console.log('params:', params);

    setLoading(true);
    setError(null);

    try {
      // OAuth2同意結果をサーバーに送信
      const consentData = new URLSearchParams();
      consentData.append('client_id', params.client_id);
      consentData.append('redirect_uri', params.redirect_uri);
      consentData.append('response_type', params.response_type);
      consentData.append('scope', params.scope);
      consentData.append('state', params.state);
      if (params.code_challenge) {
        consentData.append('code_challenge', params.code_challenge);
        consentData.append('code_challenge_method', params.code_challenge_method || 'S256');
      }
      consentData.append('consent', approve ? 'approve' : 'deny');

      const token = localStorage.getItem('accessToken');
      console.log('Using token:', token ? token.substring(0, 20) + '...' : 'null');
      console.log('Request body:', consentData.toString());

      // POSTの代わりにGETリクエストでリダイレクト（クエリパラメータで同意結果を送信）
      const url = new URL(`${getAPIGatewayBaseURL()}/api/v1/oauth2/authorize`);
      url.searchParams.set('client_id', params.client_id);
      url.searchParams.set('redirect_uri', params.redirect_uri);
      url.searchParams.set('response_type', params.response_type);
      url.searchParams.set('scope', params.scope);
      url.searchParams.set('state', params.state);
      if (params.code_challenge) {
        url.searchParams.set('code_challenge', params.code_challenge);
        url.searchParams.set('code_challenge_method', params.code_challenge_method || 'S256');
      }
      url.searchParams.set('consent', approve ? 'approve' : 'deny');
      url.searchParams.set('auth_token', token || '');

      console.log('Redirecting to:', url.toString());
      window.location.href = url.toString();
    } catch (error) {
      console.error('Consent error:', error);
      setError(`ネットワークエラーが発生しました: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const getScopeDescription = (scope: string): string[] => {
    const scopes = scope.split(' ');
    const descriptions: string[] = [];
    
    scopes.forEach(s => {
      switch (s.toLowerCase()) {
        case 'read':
          descriptions.push('アカウント情報の読み取り');
          break;
        case 'write':
          descriptions.push('データの作成・更新');
          break;
        case 'delete':
          descriptions.push('データの削除');
          break;
        default:
          descriptions.push(s);
      }
    });
    
    return descriptions;
  };

  if (error) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <h1 className="auth-title">❌ エラー</h1>
            <p className="error-message">{error}</p>
            <button 
              onClick={() => navigate('/dashboard')} 
              className="btn-primary"
              style={{ marginTop: '1rem' }}
            >
              ダッシュボードに戻る
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!params) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div style={{ textAlign: 'center' }}>
            <h1 className="auth-title">🔄 読み込み中...</h1>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h1 className="auth-title">🔐 Glen ID</h1>
          <p className="auth-subtitle">アプリケーションの認証</p>
        </div>

        <div style={{ 
          background: 'var(--color-primary-50)', 
          padding: '1.5rem', 
          borderRadius: '8px', 
          marginBottom: '1.5rem',
          border: '1px solid var(--color-primary-200)'
        }}>
          <h3 style={{ margin: '0 0 1rem 0', color: 'var(--color-primary-700)' }}>
            認証リクエスト
          </h3>
          <p style={{ margin: '0.5rem 0', fontSize: '0.9rem' }}>
            <strong>アプリケーション:</strong> {params.client_id}
          </p>
          <p style={{ margin: '0.5rem 0', fontSize: '0.9rem' }}>
            <strong>ユーザー:</strong> {params.user_id}
          </p>
          <p style={{ margin: '0.5rem 0', fontSize: '0.9rem', color: 'var(--color-gray-600)' }}>
            このアプリケーションがあなたのアカウントへのアクセスを要求しています。
          </p>
        </div>

        <div style={{ marginBottom: '2rem' }}>
          <h4 style={{ marginBottom: '1rem', color: 'var(--color-gray-700)' }}>
            要求されている権限:
          </h4>
          <div style={{ 
            background: 'var(--color-gray-50)', 
            padding: '1rem', 
            borderRadius: '6px',
            border: '1px solid var(--color-gray-200)'
          }}>
            {getScopeDescription(params.scope).map((desc, index) => (
              <div 
                key={index}
                style={{ 
                  padding: '0.5rem 0', 
                  borderBottom: index < getScopeDescription(params.scope).length - 1 ? '1px solid var(--color-gray-200)' : 'none',
                  fontSize: '0.9rem'
                }}
              >
                • {desc}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button
            onClick={() => handleConsent(false)}
            disabled={loading}
            style={{
              flex: 1,
              padding: '12px 24px',
              border: '2px solid var(--color-red-500)',
              borderRadius: '6px',
              background: 'white',
              color: 'var(--color-red-600)',
              fontSize: '1rem',
              fontWeight: '500',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.2s',
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                e.currentTarget.style.background = 'var(--color-red-500)';
                e.currentTarget.style.color = 'white';
              }
            }}
            onMouseLeave={(e) => {
              if (!loading) {
                e.currentTarget.style.background = 'white';
                e.currentTarget.style.color = 'var(--color-red-600)';
              }
            }}
          >
            {loading ? '処理中...' : '拒否'}
          </button>
          
          <button
            onClick={() => handleConsent(true)}
            disabled={loading}
            className="btn-primary"
            style={{ flex: 1 }}
          >
            {loading ? '処理中...' : '許可'}
          </button>
        </div>

        <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
          <p style={{ fontSize: '0.8rem', color: 'var(--color-gray-500)' }}>
            許可することで、このアプリケーションが上記の権限でアカウントにアクセスできるようになります。
          </p>
        </div>
      </div>
    </div>
  );
};

export default OAuth2Consent;