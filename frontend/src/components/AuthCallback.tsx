import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { SocialService } from '../services/socialService';
import { AuthService } from '../services/authService';
import { UserService } from '../services/userService';
import { getErrorMessage } from '../utils/errorUtils';

const AuthCallback: React.FC = () => {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    // すでにログイン済みの場合はダッシュボードにリダイレクト
    if (user) {
      navigate('/dashboard');
      return;
    }

    handleCallback();
  }, [user, navigate]);

  const handleCallback = async () => {
    try {
      setStatus('processing');

      // OAuth2コールバック処理
      const callbackResponse = await SocialService.handleOAuth2Callback();

      // トークンとユーザー情報を保存
      UserService.storeUser(callbackResponse.user);
      AuthService.storeTokens({
        access_token: callbackResponse.access_token,
        refresh_token: callbackResponse.refresh_token,
        expires_in: callbackResponse.expires_in,
        token_type: callbackResponse.token_type,
        scopes: callbackResponse.scopes,
      });

      // ユーザー名もローカルストレージに保存（トークンリフレッシュ用）
      localStorage.setItem('username', callbackResponse.user.username);

      setStatus('success');

      // 少し待ってからダッシュボードにリダイレクト
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);

    } catch (error: unknown) {
      console.error('OAuth2 callback failed:', error);
      const errorMessage = getErrorMessage(error, 'ソーシャルログインに失敗しました');
      setError(errorMessage);
      setStatus('error');

      // エラー時は5秒後にログインページにリダイレクト
      setTimeout(() => {
        navigate('/login');
      }, 5000);
    }
  };

  const renderContent = () => {
    switch (status) {
      case 'processing':
        return (
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              width: '3rem', 
              height: '3rem', 
              border: '4px solid #f3f4f6',
              borderTop: '4px solid var(--color-primary-600)',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
              margin: '0 auto 1rem'
            }}></div>
            <h2 style={{ 
              fontSize: '1.5rem', 
              fontWeight: 600, 
              color: '#1f2937',
              marginBottom: '0.5rem'
            }}>
              認証処理中...
            </h2>
            <p style={{ color: '#6b7280' }}>
              ソーシャルログインの認証を処理しています。しばらくお待ちください。
            </p>
          </div>
        );

      case 'success':
        return (
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              fontSize: '3rem', 
              marginBottom: '1rem' 
            }}>
              ✅
            </div>
            <h2 style={{ 
              fontSize: '1.5rem', 
              fontWeight: 600, 
              color: '#059669',
              marginBottom: '0.5rem'
            }}>
              ログイン成功！
            </h2>
            <p style={{ color: '#6b7280' }}>
              ダッシュボードにリダイレクトしています...
            </p>
          </div>
        );

      case 'error':
        return (
          <div style={{ textAlign: 'center' }}>
            <div style={{ 
              fontSize: '3rem', 
              marginBottom: '1rem' 
            }}>
              ❌
            </div>
            <h2 style={{ 
              fontSize: '1.5rem', 
              fontWeight: 600, 
              color: '#dc2626',
              marginBottom: '0.5rem'
            }}>
              ログインに失敗しました
            </h2>
            <p style={{ 
              color: '#6b7280',
              marginBottom: '1rem'
            }}>
              {error}
            </p>
            <p style={{ 
              fontSize: '0.875rem',
              color: '#9ca3af'
            }}>
              5秒後にログインページにリダイレクトします...
            </p>
          </div>
        );
    }
  };

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
        borderRadius: '1rem',
        boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
        padding: '3rem 2rem',
        width: '100%',
        maxWidth: '28rem'
      }}>
        {renderContent()}
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default AuthCallback;