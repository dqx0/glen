import { useState } from 'react';
import { SocialService } from '../services/socialService';
import type { SocialProvider } from '../types/social';

interface SocialLoginButtonProps {
  provider: SocialProvider;
  onError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
  mode?: 'login' | 'link'; // ログイン用か連携用かを指定
}

const SocialLoginButton: React.FC<SocialLoginButtonProps> = ({
  provider,
  onError,
  disabled = false,
  className = '',
  mode = 'link',
}) => {
  const [loading, setLoading] = useState(false);
  const providerInfo = SocialService.getProviderInfo(provider);

  const handleSocialLogin = async () => {
    if (disabled || loading) return;

    try {
      setLoading(true);
      
      // 同じリダイレクトURIを使用（モードはsessionStorageで判別）
      const redirectUri = `${window.location.origin}/auth/callback`;
      
      // stateにモード情報を含める
      const state = SocialService.generateState();
      
      // 認証URLを取得
      const authResponse = await SocialService.authorize({
        provider,
        redirect_uri: redirectUri,
        state,
      });

      // sessionStorageに保存
      sessionStorage.setItem('oauth2_state', state);
      sessionStorage.setItem('oauth2_provider', provider);
      sessionStorage.setItem('oauth2_redirect_uri', redirectUri);
      sessionStorage.setItem('oauth2_mode', mode);

      // 認証ページにリダイレクト
      const authUrl = authResponse.authorization_url || authResponse.auth_url;
      if (!authUrl) {
        throw new Error('Authorization URL not found in response');
      }
      window.location.href = authUrl;
    } catch (error: any) {
      console.error(`Social ${mode} failed for ${provider}:`, error);
      const errorMessage = error.response?.data?.message || error.message || `ソーシャル${mode === 'login' ? 'ログイン' : '連携'}に失敗しました`;
      onError?.(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleSocialLogin}
      disabled={disabled || loading}
      className={`
        w-full flex items-center justify-center px-4 py-3 border border-transparent 
        text-sm font-medium rounded-lg text-white focus:outline-none focus:ring-2 
        focus:ring-offset-2 transition-all duration-200 disabled:opacity-50 
        disabled:cursor-not-allowed hover:transform hover:scale-105 
        ${className}
      `}
      style={{
        backgroundColor: providerInfo.bgColor,
        color: providerInfo.textColor,
      }}
    >
      <span className="mr-3 text-lg">{providerInfo.icon}</span>
      {loading ? (
        <span>接続中...</span>
      ) : (
        <span>{providerInfo.name}でログイン</span>
      )}
    </button>
  );
};

export default SocialLoginButton;