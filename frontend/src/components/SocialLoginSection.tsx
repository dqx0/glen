import { useState, useEffect } from 'react';
import { SocialService } from '../services/socialService';
import SocialLoginButton from './SocialLoginButton';
import type { SocialProvider } from '../types/social';

interface SocialLoginSectionProps {
  onError?: (error: string) => void;
  disabled?: boolean;
  mode?: 'login' | 'link';
}

const SocialLoginSection: React.FC<SocialLoginSectionProps> = ({
  onError,
  disabled = false,
  mode = 'login',
}) => {
  const [availableProviders, setAvailableProviders] = useState<SocialProvider[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProviders();
  }, []);

  const loadProviders = async () => {
    try {
      const response = await SocialService.getProviders();
      const enabledProviders = response.providers
        .filter(p => p.enabled)
        .map(p => p.provider);
      setAvailableProviders(enabledProviders);
    } catch (error) {
      console.error('Failed to load social providers:', error);
      // エラーでもデフォルトプロバイダーを表示
      setAvailableProviders(['google', 'github', 'discord']);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '1rem' }}>
        <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
          ソーシャルログインオプションを読み込み中...
        </div>
      </div>
    );
  }

  if (availableProviders.length === 0) {
    return null;
  }

  return (
    <div>
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        margin: '1.5rem 0',
        textAlign: 'center' 
      }}>
        <div style={{ 
          flex: 1, 
          height: '1px', 
          backgroundColor: '#e5e7eb' 
        }}></div>
        <span style={{ 
          padding: '0 1rem', 
          fontSize: '0.875rem', 
          color: '#6b7280',
          backgroundColor: 'white'
        }}>
          または
        </span>
        <div style={{ 
          flex: 1, 
          height: '1px', 
          backgroundColor: '#e5e7eb' 
        }}></div>
      </div>

      <div style={{ 
        display: 'flex', 
        flexDirection: 'column', 
        gap: '0.75rem' 
      }}>
        {availableProviders.map((provider) => (
          <SocialLoginButton
            key={provider}
            provider={provider}
            onError={onError}
            disabled={disabled}
            mode={mode}
          />
        ))}
      </div>
    </div>
  );
};

export default SocialLoginSection;