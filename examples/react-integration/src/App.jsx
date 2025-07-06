/**
 * React アプリケーションでの Glen ID Platform 統合サンプル
 * 
 * このファイルは、React アプリケーションで Glen ID Platform を使用する
 * 完全な例を示しています。
 */

import React, { useState } from 'react';
import './App.css';
import {
  GlenIdProvider,
  useGlenId,
  LoginButton,
  LogoutButton,
  UserProfile,
  ProtectedRoute,
  ErrorDisplay,
  ConditionalAuth,
  useWebAuthnCredentials,
  useSocialAccounts,
  useApiKeys
} from './components/GlenAuth';

// Glen ID SDK の設定
const glenIdConfig = {
  baseUrl: 'https://glen.dqx0.com',
  apiBaseUrl: 'https://api.glen.dqx0.com/api/v1',
  clientId: 'my-react-app',
  redirectUri: window.location.origin + '/auth/callback',
  scopes: ['read', 'write'],
  debug: process.env.NODE_ENV === 'development'
};

/**
 * メインアプリケーションコンポーネント
 */
function AppContent() {
  const { isAuthenticated, isLoading, user } = useGlenId();

  if (isLoading) {
    return (
      <div className="app-loading">
        <div className="loading-spinner"></div>
        <p>Glen ID を初期化中...</p>
      </div>
    );
  }

  return (
    <div className="app">
      <Header />
      <ErrorDisplay />
      <main className="main-content">
        <ConditionalAuth
          authenticated={<AuthenticatedContent />}
          unauthenticated={<UnauthenticatedContent />}
        />
      </main>
      <Footer />
    </div>
  );
}

/**
 * ヘッダーコンポーネント
 */
function Header() {
  return (
    <header className="app-header">
      <div className="container">
        <h1 className="app-title">My App with Glen ID</h1>
        <nav className="nav">
          <ConditionalAuth
            authenticated={
              <div className="nav-authenticated">
                <UserProfile />
                <LogoutButton className="btn-secondary">
                  ログアウト
                </LogoutButton>
              </div>
            }
            unauthenticated={
              <LoginButton className="btn-primary">
                ログイン
              </LoginButton>
            }
          />
        </nav>
      </div>
    </header>
  );
}

/**
 * 未認証時のコンテンツ
 */
function UnauthenticatedContent() {
  return (
    <div className="welcome-section">
      <div className="container">
        <div className="hero">
          <h2>Glen ID Platform へようこそ</h2>
          <p>
            統合認証基盤 Glen ID を使用して、安全で便利な認証体験を提供します。
            複数の認証方式（パスワード、WebAuthn、ソーシャルログイン）をサポートしています。
          </p>
          <div className="cta-buttons">
            <LoginButton className="btn-primary btn-large">
              🔐 Glen ID でログイン
            </LoginButton>
          </div>
        </div>
        
        <div className="features">
          <h3>主な機能</h3>
          <div className="feature-grid">
            <div className="feature-card">
              <div className="feature-icon">🔑</div>
              <h4>パスワード認証</h4>
              <p>従来のユーザー名・パスワードによる安全な認証</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">👆</div>
              <h4>WebAuthn認証</h4>
              <p>指紋認証やセキュリティキーによるパスワードレス認証</p>
            </div>
            <div className="feature-card">
              <div className="feature-icon">🌐</div>
              <h4>ソーシャルログイン</h4>
              <p>Google、GitHub、Discordアカウントでの簡単ログイン</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * 認証済み時のコンテンツ
 */
function AuthenticatedContent() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className="authenticated-content">
      <div className="container">
        <div className="content-tabs">
          <nav className="tab-nav">
            <button 
              className={`tab-button ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActiveTab('dashboard')}
            >
              📊 ダッシュボード
            </button>
            <button 
              className={`tab-button ${activeTab === 'webauthn' ? 'active' : ''}`}
              onClick={() => setActiveTab('webauthn')}
            >
              👆 WebAuthn
            </button>
            <button 
              className={`tab-button ${activeTab === 'social' ? 'active' : ''}`}
              onClick={() => setActiveTab('social')}
            >
              🌐 ソーシャル連携
            </button>
            <button 
              className={`tab-button ${activeTab === 'api-keys' ? 'active' : ''}`}
              onClick={() => setActiveTab('api-keys')}
            >
              🔑 APIキー
            </button>
          </nav>

          <div className="tab-content">
            {activeTab === 'dashboard' && <Dashboard />}
            {activeTab === 'webauthn' && <WebAuthnSection />}
            {activeTab === 'social' && <SocialAccountsSection />}
            {activeTab === 'api-keys' && <ApiKeysSection />}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * ダッシュボードコンポーネント
 */
function Dashboard() {
  const { user } = useGlenId();

  return (
    <div className="dashboard">
      <h2>ダッシュボード</h2>
      <div className="dashboard-grid">
        <div className="dashboard-card">
          <h3>👤 プロフィール情報</h3>
          <div className="profile-details">
            <div className="profile-row">
              <label>ユーザー名:</label>
              <span>{user?.username}</span>
            </div>
            <div className="profile-row">
              <label>メールアドレス:</label>
              <span>{user?.email}</span>
            </div>
            <div className="profile-row">
              <label>作成日:</label>
              <span>{new Date(user?.created_at).toLocaleDateString('ja-JP')}</span>
            </div>
          </div>
        </div>

        <div className="dashboard-card">
          <h3>🔒 認証状態</h3>
          <div className="auth-status">
            <div className="status-item">
              <span className="status-indicator success"></span>
              <span>Glen ID 認証済み</span>
            </div>
          </div>
        </div>

        <div className="dashboard-card">
          <h3>📊 最近のアクティビティ</h3>
          <div className="activity-list">
            <div className="activity-item">
              <span className="activity-time">
                {new Date().toLocaleTimeString('ja-JP')}
              </span>
              <span className="activity-description">
                ダッシュボードにアクセス
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * WebAuthn認証器管理セクション
 */
function WebAuthnSection() {
  const { credentials, loading, refresh } = useWebAuthnCredentials();

  return (
    <div className="webauthn-section">
      <div className="section-header">
        <h2>👆 WebAuthn認証器</h2>
        <button onClick={refresh} className="btn-secondary" disabled={loading}>
          {loading ? '更新中...' : '🔄 更新'}
        </button>
      </div>

      {loading ? (
        <div className="loading">WebAuthn認証器を読み込み中...</div>
      ) : (
        <div className="credentials-list">
          {credentials.length === 0 ? (
            <div className="empty-state">
              <p>WebAuthn認証器が登録されていません</p>
              <p className="empty-description">
                指紋認証やセキュリティキーを追加してパスワードレス認証を有効にできます
              </p>
            </div>
          ) : (
            <div className="credentials-grid">
              {credentials.map((credential) => (
                <div key={credential.id} className="credential-card">
                  <div className="credential-header">
                    <span className="credential-icon">
                      {getCredentialIcon(credential)}
                    </span>
                    <h4>{credential.name}</h4>
                  </div>
                  <div className="credential-details">
                    <div className="detail-row">
                      <label>種類:</label>
                      <span>{getCredentialType(credential)}</span>
                    </div>
                    <div className="detail-row">
                      <label>登録日:</label>
                      <span>{new Date(credential.created_at).toLocaleDateString('ja-JP')}</span>
                    </div>
                    <div className="detail-row">
                      <label>最終使用:</label>
                      <span>
                        {credential.last_used_at 
                          ? new Date(credential.last_used_at).toLocaleDateString('ja-JP')
                          : '未使用'
                        }
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * ソーシャルアカウント連携セクション
 */
function SocialAccountsSection() {
  const { accounts, loading, refresh } = useSocialAccounts();

  return (
    <div className="social-section">
      <div className="section-header">
        <h2>🌐 ソーシャルアカウント連携</h2>
        <button onClick={refresh} className="btn-secondary" disabled={loading}>
          {loading ? '更新中...' : '🔄 更新'}
        </button>
      </div>

      {loading ? (
        <div className="loading">ソーシャルアカウントを読み込み中...</div>
      ) : (
        <div className="social-accounts">
          {accounts.length === 0 ? (
            <div className="empty-state">
              <p>連携済みソーシャルアカウントがありません</p>
              <p className="empty-description">
                Google、GitHub、Discordアカウントと連携して便利にログインできます
              </p>
            </div>
          ) : (
            <div className="accounts-grid">
              {accounts.map((account) => (
                <div key={account.provider} className="account-card">
                  <div className="account-header">
                    <span className="provider-icon">
                      {getProviderIcon(account.provider)}
                    </span>
                    <h4>{getProviderName(account.provider)}</h4>
                  </div>
                  <div className="account-details">
                    <div className="detail-row">
                      <label>ユーザー名:</label>
                      <span>{account.username}</span>
                    </div>
                    <div className="detail-row">
                      <label>メール:</label>
                      <span>{account.email}</span>
                    </div>
                    <div className="detail-row">
                      <label>連携日:</label>
                      <span>{new Date(account.connected_at).toLocaleDateString('ja-JP')}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * APIキー管理セクション
 */
function ApiKeysSection() {
  const { tokens, loading, createToken, refresh } = useApiKeys();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newTokenData, setNewTokenData] = useState({
    name: '',
    scopes: ['read']
  });

  const handleCreateToken = async (e) => {
    e.preventDefault();
    const result = await createToken(newTokenData);
    if (result) {
      setShowCreateForm(false);
      setNewTokenData({ name: '', scopes: ['read'] });
      alert(`APIキーが作成されました: ${result.api_key}`);
    }
  };

  return (
    <div className="api-keys-section">
      <div className="section-header">
        <h2>🔑 APIキー管理</h2>
        <div className="header-actions">
          <button onClick={refresh} className="btn-secondary" disabled={loading}>
            {loading ? '更新中...' : '🔄 更新'}
          </button>
          <button 
            onClick={() => setShowCreateForm(!showCreateForm)} 
            className="btn-primary"
          >
            ➕ APIキー作成
          </button>
        </div>
      </div>

      {showCreateForm && (
        <div className="create-token-form">
          <h3>新しいAPIキーを作成</h3>
          <form onSubmit={handleCreateToken}>
            <div className="form-group">
              <label>APIキー名:</label>
              <input
                type="text"
                value={newTokenData.name}
                onChange={(e) => setNewTokenData({...newTokenData, name: e.target.value})}
                placeholder="例：My Application API Key"
                required
              />
            </div>
            <div className="form-group">
              <label>スコープ:</label>
              <div className="scope-checkboxes">
                {['read', 'write', 'admin'].map(scope => (
                  <label key={scope} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={newTokenData.scopes.includes(scope)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setNewTokenData({
                            ...newTokenData,
                            scopes: [...newTokenData.scopes, scope]
                          });
                        } else {
                          setNewTokenData({
                            ...newTokenData,
                            scopes: newTokenData.scopes.filter(s => s !== scope)
                          });
                        }
                      }}
                    />
                    {scope}
                  </label>
                ))}
              </div>
            </div>
            <div className="form-actions">
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? '作成中...' : '作成'}
              </button>
              <button 
                type="button" 
                onClick={() => setShowCreateForm(false)}
                className="btn-secondary"
              >
                キャンセル
              </button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div className="loading">APIキーを読み込み中...</div>
      ) : (
        <div className="tokens-list">
          {tokens.length === 0 ? (
            <div className="empty-state">
              <p>APIキーが作成されていません</p>
              <p className="empty-description">
                APIキーを作成して外部サービスからアクセスできるようにしましょう
              </p>
            </div>
          ) : (
            <div className="tokens-grid">
              {tokens.map((token) => (
                <div key={token.id} className="token-card">
                  <div className="token-header">
                    <h4>{token.name}</h4>
                    <span className={`token-type ${token.token_type}`}>
                      {token.token_type === 'api_key' ? 'APIキー' : 'セッション'}
                    </span>
                  </div>
                  <div className="token-details">
                    <div className="detail-row">
                      <label>スコープ:</label>
                      <span>{token.scopes.join(', ')}</span>
                    </div>
                    <div className="detail-row">
                      <label>作成日:</label>
                      <span>{new Date(token.created_at).toLocaleDateString('ja-JP')}</span>
                    </div>
                    {token.last_used_at && (
                      <div className="detail-row">
                        <label>最終使用:</label>
                        <span>{new Date(token.last_used_at).toLocaleDateString('ja-JP')}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * フッターコンポーネント
 */
function Footer() {
  return (
    <footer className="app-footer">
      <div className="container">
        <p>&copy; 2024 Glen ID Platform Integration Sample</p>
        <div className="footer-links">
          <a href="https://github.com/dqx0/glen" target="_blank" rel="noopener noreferrer">
            GitHub
          </a>
          <a href="https://api.glen.dqx0.com/docs" target="_blank" rel="noopener noreferrer">
            API ドキュメント
          </a>
        </div>
      </div>
    </footer>
  );
}

/**
 * ユーティリティ関数
 */
function getCredentialIcon(credential) {
  if (credential.transport.includes('internal')) {
    return '📱'; // プラットフォーム認証器
  } else if (credential.transport.includes('usb')) {
    return '🔑'; // USBセキュリティキー
  } else if (credential.transport.includes('nfc')) {
    return '📡'; // NFC
  } else if (credential.transport.includes('ble')) {
    return '📶'; // Bluetooth
  }
  return '🔐'; // 汎用
}

function getCredentialType(credential) {
  if (credential.transport.includes('internal')) {
    return 'プラットフォーム認証器';
  } else if (credential.transport.some(t => ['usb', 'nfc', 'ble'].includes(t))) {
    return 'ローミング認証器';
  }
  return '不明';
}

function getProviderIcon(provider) {
  const icons = {
    google: '🟡',
    github: '⚫',
    discord: '🟣'
  };
  return icons[provider] || '🌐';
}

function getProviderName(provider) {
  const names = {
    google: 'Google',
    github: 'GitHub',
    discord: 'Discord'
  };
  return names[provider] || provider;
}

/**
 * メインAppコンポーネント
 */
function App() {
  return (
    <GlenIdProvider config={glenIdConfig}>
      <AppContent />
    </GlenIdProvider>
  );
}

export default App;