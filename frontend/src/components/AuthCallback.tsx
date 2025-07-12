import { useEffect, useState, useRef } from 'react';
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
  const { user, refreshUser } = useAuth();
  const hasProcessed = useRef(false);

  useEffect(() => {
    // すでにログイン済みの場合はダッシュボードにリダイレクト
    if (user) {
      navigate('/dashboard');
      return;
    }

    // 初回のみ実行（重複実行を防ぐ）
    if (!hasProcessed.current) {
      hasProcessed.current = true;
      handleCallback();
    }
  }, [user, navigate]);

  const handleCallback = async () => {
    console.log('handleCallback called', { hasProcessed: hasProcessed.current });
    
    // 重複実行を防ぐ
    if (hasProcessed.current && status !== 'processing') {
      console.log('Duplicate call prevented');
      return;
    }

    try {
      // モードを確認（ログインか連携か）
      const mode = sessionStorage.getItem('oauth2_mode') || 'link';
      console.log('OAuth2 callback mode:', mode);
      
      let callbackResponse;
      
      if (mode === 'login') {
        // ソーシャルログイン処理
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const savedProvider = sessionStorage.getItem('oauth2_provider') as any;
        const savedRedirectUri = sessionStorage.getItem('oauth2_redirect_uri');
        
        if (!code || !state || !savedProvider || !savedRedirectUri) {
          throw new Error('Missing OAuth2 parameters for social login');
        }
        
        const socialLoginResponse = await SocialService.socialLogin({
          provider: savedProvider,
          code,
          state,
          redirect_uri: savedRedirectUri,
        });
        
        console.log('Social login response:', socialLoginResponse);
        
        // まずダミーのユーザー名でJWTトークンを発行
        const authResponse = await AuthService.login({
          user_id: socialLoginResponse.user_id,
          username: 'social-user', // 仮のユーザー名
          session_name: 'social-session',
          scopes: ['read', 'write'],
        });
        
        console.log('JWT token received for social login');
        
        // トークンを先に設定（これでAPI認証が通る）
        AuthService.storeTokens(authResponse);
        
        // トークンが設定された状態でユーザー情報を取得
        const userData = await UserService.getUserById(socialLoginResponse.user_id);
        console.log('User data loaded for social login:', userData);
        
        // ユーザー情報を保存
        UserService.storeUser(userData);
        localStorage.setItem('username', userData.username);
        
        setStatus('success');
        setTimeout(() => {
          navigate('/dashboard');
        }, 2000);
        return;
      } else {
        // アカウント連携処理（既存）
        callbackResponse = await SocialService.handleOAuth2Callback();
      }
      
      console.log('Callback response:', callbackResponse);

      // ソーシャルアカウント連携が成功した場合
      if (callbackResponse.social_account) {
        console.log('Social account linking successful:', callbackResponse.social_account);
        setStatus('success');
        
        // ユーザー情報を更新（ログイン済みユーザーの場合）
        if (user) {
          console.log('User is logged in, refreshing user data...');
          try {
            await refreshUser();
          } catch (error) {
            console.error('Failed to refresh user data:', error);
          }
        } else {
          console.log('No user logged in - this should not happen as callback requires authentication');
          // この状況は発生しないはずです（API Gatewayで認証チェック済み）
          setError('認証エラー: ソーシャルアカウント連携にはログインが必要です');
          setStatus('error');
          setTimeout(() => {
            navigate('/login');
          }, 3000);
          return;
        }
        
        // 少し待ってからダッシュボードにリダイレクト（アカウント連携完了）
        setTimeout(() => {
          console.log('Redirecting to dashboard...');
          navigate('/dashboard?social_linked=true');
        }, 2000);
        return;
      }

      // レスポンスに期待するデータがない場合
      console.log('No social_account in response, treating as error');
      setError('ソーシャルログインの処理に失敗しました');
      setStatus('error');
      setTimeout(() => {
        navigate('/login');
      }, 5000);

    } catch (error: unknown) {
      console.error('OAuth2 callback failed:', error);
      const errorMessage = getErrorMessage(error, 'ソーシャルログインに失敗しました');
      
      // 特定のエラーメッセージに基づいてユーザーフレンドリーなメッセージを表示
      if (errorMessage.includes('social login user registration not implemented')) {
        setError('ソーシャルログインでの新規登録は現在実装中です。先にアカウントを作成してからソーシャルアカウントを連携してください。');
      } else if (errorMessage.includes('user authentication required')) {
        setError('ソーシャルアカウント連携には、先にログインが必要です。');
      } else {
        setError(errorMessage);
      }
      
      setStatus('error');

      // エラー時は5秒後にログインページにリダイレクト
      setTimeout(() => {
        navigate('/login');
      }, 5000);
    }
  };

  const renderContent = () => {
    console.log('AuthCallback rendering with status:', status);
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