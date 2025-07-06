import { useState } from 'react';
import { SocialService } from '../services/socialService';
import type { SocialProvider } from '../types/social';

interface SocialLoginButtonProps {
  provider: SocialProvider;
  onError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
}

const SocialLoginButton: React.FC<SocialLoginButtonProps> = ({
  provider,
  onError,
  disabled = false,
  className = '',
}) => {
  const [loading, setLoading] = useState(false);
  const providerInfo = SocialService.getProviderInfo(provider);

  const handleSocialLogin = async () => {
    if (disabled || loading) return;

    try {
      setLoading(true);
      await SocialService.startOAuth2Flow(provider);
    } catch (error: any) {
      console.error(`Social login failed for ${provider}:`, error);
      const errorMessage = error.response?.data?.message || error.message || 'ソーシャルログインに失敗しました';
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