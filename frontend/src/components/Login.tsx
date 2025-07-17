import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import SocialLoginSection from './SocialLoginSection';
import WebAuthnSection from './WebAuthnSection';

const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const { login, loading, error, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // ログイン済みの場合は適切な場所にリダイレクト
  useEffect(() => {
    if (isAuthenticated) {
      const urlParams = new URLSearchParams(location.search);
      const redirectUri = urlParams.get('redirect_uri');
      
      if (redirectUri) {
        // OAuth2フローの場合、同意画面への認証済みリクエストとしてリダイレクト
        const token = localStorage.getItem('accessToken');
        if (token) {
          const url = new URL(redirectUri);
          url.searchParams.set('auth_token', token);
          window.location.href = url.toString();
        } else {
          window.location.href = redirectUri;
        }
      } else {
        navigate('/dashboard', { replace: true });
      }
    }
  }, [isAuthenticated, location.search, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username || !password) {
      return;
    }

    try {
      await login(username, password);
      
      // 少し待ってから遷移（ユーザー状態の更新を待つ）
      setTimeout(() => {
        const urlParams = new URLSearchParams(location.search);
        const redirectUri = urlParams.get('redirect_uri');
        
        if (redirectUri) {
          // OAuth2フロー用に認証トークンをクエリパラメータで含めてリダイレクト
          const token = localStorage.getItem('accessToken');
          if (token) {
            const url = new URL(redirectUri);
            url.searchParams.set('auth_token', token);
            window.location.href = url.toString();
          } else {
            window.location.href = redirectUri;
          }
        } else {
          navigate('/dashboard');
        }
      }, 100);
    } catch (error) {
      // エラーはAuthContextで処理済み
      console.error('Login failed:', error);
    }
  };

  // ログイン済みの場合はローディング表示
  if (isAuthenticated) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <h1 className="auth-title">Glen ID</h1>
            <p className="auth-subtitle">リダイレクト中...</p>
            <div style={{ marginTop: '1rem' }}>
              <div className="spinner"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h1 className="auth-title">Glen ID</h1>
          <p className="auth-subtitle">アカウントにログイン</p>
        </div>
        
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div>
            <label htmlFor="username" className="form-label">
              ユーザー名
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
              placeholder="ユーザー名を入力"
              className="form-input"
            />
          </div>
          
          <div>
            <label htmlFor="password" className="form-label">
              パスワード
            </label>
            <div style={{ position: 'relative' }}>
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                placeholder="パスワードを入力"
                className="form-input"
                style={{ paddingRight: '3rem' }}
              />
              <button
                type="button"
                style={{
                  position: 'absolute',
                  top: '50%',
                  right: '0.75rem',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center'
                }}
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? (
                  <EyeSlashIcon style={{ width: '1.25rem', height: '1.25rem', color: '#9ca3af' }} />
                ) : (
                  <EyeIcon style={{ width: '1.25rem', height: '1.25rem', color: '#9ca3af' }} />
                )}
              </button>
            </div>
          </div>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className="btn-primary"
            disabled={loading || !username || !password}
          >
            {loading ? 'ログイン中...' : 'ログイン'}
          </button>
        </form>

        {/* WebAuthn認証 */}
        <WebAuthnSection 
          onError={(error) => {
            console.error('WebAuthn error:', error);
          }}
          disabled={loading}
        />

        {/* ソーシャルログイン */}
        <SocialLoginSection 
          onError={(error) => {
            // エラーをメイン認証エラーに設定（認証コンテキストのエラーを使用）
            console.error('Social login error:', error);
          }}
          disabled={loading}
        />

        <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
          <p style={{ fontSize: '0.875rem', color: '#6b7280' }}>
            アカウントをお持ちでない場合は{' '}
            <Link 
              to="/register" 
              style={{ 
                fontWeight: 500, 
                color: 'var(--color-primary-600)', 
                textDecoration: 'none' 
              }}
            >
              アカウントを作成
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;