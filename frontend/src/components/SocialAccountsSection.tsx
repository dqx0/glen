import { useState, useEffect } from 'react';
import { SocialService } from '../services/socialService';
import SocialLoginButton from './SocialLoginButton';
import type { SocialAccount, SocialProvider } from '../types/social';
import { 
  TrashIcon,
  LinkIcon,
  UserIcon,
  ClockIcon 
} from '@heroicons/react/24/outline';

const SocialAccountsSection: React.FC = () => {
  const [socialAccounts, setSocialAccounts] = useState<SocialAccount[]>([]);
  const [availableProviders, setAvailableProviders] = useState<SocialProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // 並行して実行 - より堅牢なエラーハンドリング
      const [accountsResponse, providersResponse] = await Promise.all([
        SocialService.getSocialAccounts().catch((error) => {
          console.warn('Failed to load social accounts:', error);
          return { accounts: [] };
        }),
        SocialService.getProviders().catch((error) => {
          console.warn('Failed to load social providers:', error);
          return { providers: [] };
        })
      ]);

      // 安全な配列アクセス
      const accounts = Array.isArray(accountsResponse?.accounts) ? accountsResponse.accounts : [];
      setSocialAccounts(accounts);
      
      // プロバイダーの安全な処理
      const providers = Array.isArray(providersResponse?.providers) ? providersResponse.providers : [];
      const enabledProviders = providers
        .filter(p => p && typeof p === 'object' && p.enabled)
        .map(p => p.provider)
        .filter(p => p); // null/undefined を除外
      setAvailableProviders(enabledProviders);
      
    } catch (error: any) {
      console.error('Failed to load social accounts data:', error);
      setError('ソーシャルアカウント情報の読み込みに失敗しました');
      // エラー時のフォールバック
      setSocialAccounts([]);
      setAvailableProviders([]);
    } finally {
      setLoading(false);
    }
  };

  const handleUnlinkAccount = async (accountId: string) => {
    if (!confirm('このソーシャルアカウントの連携を解除しますか？')) {
      return;
    }

    try {
      await SocialService.unlinkAccount({ account_id: accountId });
      await loadData(); // データを再読み込み
    } catch (error: any) {
      console.error('Failed to unlink account:', error);
      setError('アカウント連携の解除に失敗しました');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('ja-JP');
  };

  const getConnectedProviders = () => {
    return socialAccounts.map(account => account.provider);
  };

  const getUnconnectedProviders = () => {
    const connectedProviders = getConnectedProviders();
    return availableProviders.filter(provider => !connectedProviders.includes(provider));
  };

  if (loading) {
    return (
      <div style={{ 
        backgroundColor: 'white', 
        borderRadius: '0.5rem', 
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        padding: '1.5rem' 
      }}>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
            ソーシャルアカウント情報を読み込み中...
          </div>
        </div>
      </div>
    );
  }

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
        marginBottom: '1.5rem' 
      }}>
        <LinkIcon style={{ 
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
          ソーシャルアカウント連携
        </h3>
      </div>

      {error && (
        <div className="error-message" style={{ marginBottom: '1.5rem' }}>
          {error}
        </div>
      )}

      {/* 連携済みアカウント */}
      {socialAccounts.length > 0 && (
        <div style={{ marginBottom: '2rem' }}>
          <h4 style={{ 
            fontSize: '1rem', 
            fontWeight: 500, 
            color: '#1f2937',
            marginBottom: '1rem'
          }}>
            連携済みアカウント
          </h4>
          <div style={{ 
            display: 'grid', 
            gap: '1rem', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' 
          }}>
            {socialAccounts.map((account) => {
              const providerInfo = SocialService.getProviderInfo(account.provider);
              return (
                <div
                  key={account.id}
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
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <span style={{ fontSize: '1.25rem', marginRight: '0.5rem' }}>
                        {providerInfo.icon}
                      </span>
                      <h5 style={{ 
                        fontSize: '0.875rem', 
                        fontWeight: 500, 
                        color: '#1f2937',
                        margin: 0
                      }}>
                        {providerInfo.name}
                      </h5>
                    </div>
                    <span style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      padding: '0.25rem 0.625rem',
                      borderRadius: '9999px',
                      fontSize: '0.75rem',
                      fontWeight: 500,
                      backgroundColor: '#dcfce7',
                      color: '#166534'
                    }}>
                      連携済み
                    </span>
                  </div>
                  
                  <div style={{ 
                    fontSize: '0.75rem', 
                    color: '#6b7280',
                    marginBottom: '0.75rem'
                  }}>
                    <div style={{ 
                      display: 'flex', 
                      alignItems: 'center',
                      marginBottom: '0.25rem'
                    }}>
                      <UserIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                      <span style={{ fontWeight: 500 }}>名前:</span>
                      <span style={{ marginLeft: '0.25rem' }}>{account.name || 'N/A'}</span>
                    </div>
                    {account.email && (
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center',
                        marginBottom: '0.25rem'
                      }}>
                        <span style={{ fontWeight: 500 }}>メール:</span>
                        <span style={{ marginLeft: '0.25rem' }}>{account.email}</span>
                      </div>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <ClockIcon style={{ width: '0.75rem', height: '0.75rem', marginRight: '0.25rem' }} />
                      <span style={{ fontWeight: 500 }}>連携日:</span>
                      <span style={{ marginLeft: '0.25rem' }}>{formatDate(account.created_at)}</span>
                    </div>
                  </div>
                  
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      onClick={() => handleUnlinkAccount(account.id)}
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
                      連携解除
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 未連携プロバイダー */}
      {getUnconnectedProviders().length > 0 && (
        <div>
          <h4 style={{ 
            fontSize: '1rem', 
            fontWeight: 500, 
            color: '#1f2937',
            marginBottom: '1rem'
          }}>
            新しいアカウントを連携
          </h4>
          <div style={{ 
            display: 'grid', 
            gap: '0.75rem', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' 
          }}>
            {getUnconnectedProviders().map((provider) => (
              <SocialLoginButton
                key={provider}
                provider={provider}
                onError={(error) => setError(error)}
              />
            ))}
          </div>
        </div>
      )}

      {availableProviders.length === 0 && (
        <div style={{ 
          textAlign: 'center', 
          padding: '2rem',
          color: '#6b7280'
        }}>
          <LinkIcon style={{ 
            width: '3rem', 
            height: '3rem', 
            margin: '0 auto 0.5rem',
            color: '#d1d5db'
          }} />
          <p style={{ margin: 0 }}>利用可能なソーシャルログインプロバイダーがありません</p>
        </div>
      )}
    </div>
  );
};

export default SocialAccountsSection;