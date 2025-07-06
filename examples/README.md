# Glen ID Platform SDK と統合例

このディレクトリには、Glen ID Platform と外部サービスを統合するためのSDKとサンプルコードが含まれています。

## 📁 ディレクトリ構成

```
examples/
├── sdk/
│   └── javascript/
│       └── glen-id-sdk.js          # JavaScript SDK
├── react-integration/
│   ├── src/
│   │   ├── components/
│   │   │   └── GlenAuth.jsx        # React コンポーネント
│   │   ├── App.jsx                 # メインアプリケーション
│   │   └── App.css                 # スタイルシート
│   └── package.json
├── python-flask/
│   ├── app.py                      # Flask 統合例
│   └── requirements.txt            # Python 依存関係
└── README.md                       # このファイル
```

## 🚀 クイックスタート

### JavaScript SDK

最も簡単な使用方法：

```html
<!DOCTYPE html>
<html>
<head>
    <title>Glen ID Example</title>
</head>
<body>
    <div id="app">
        <div id="login-section">
            <button onclick="login()">Glen ID でログイン</button>
        </div>
        <div id="user-section" style="display: none;">
            <h3>ログイン済み</h3>
            <p>ユーザー名: <span id="username"></span></p>
            <button onclick="logout()">ログアウト</button>
        </div>
    </div>

    <script src="./sdk/javascript/glen-id-sdk.js"></script>
    <script>
        // Glen ID SDK を初期化
        const glenId = new GlenIdSDK({
            baseUrl: 'https://glen.dqx0.com',
            clientId: 'my-app',
            redirectUri: window.location.origin + '/callback.html',
            debug: true
        });

        // イベントリスナーを設定
        glenId.on('initialized', ({ user }) => {
            updateUI(user);
        });

        glenId.on('loginSuccess', async () => {
            const user = await glenId.fetchUserInfo();
            updateUI(user);
        });

        glenId.on('loggedOut', () => {
            updateUI(null);
        });

        // UI更新
        function updateUI(user) {
            const loginSection = document.getElementById('login-section');
            const userSection = document.getElementById('user-section');
            const usernameSpan = document.getElementById('username');

            if (user) {
                loginSection.style.display = 'none';
                userSection.style.display = 'block';
                usernameSpan.textContent = user.username;
            } else {
                loginSection.style.display = 'block';
                userSection.style.display = 'none';
            }
        }

        // ログイン/ログアウト関数
        function login() {
            glenId.login();
        }

        function logout() {
            glenId.logout();
        }
    </script>
</body>
</html>
```

### React 統合

```bash
# React プロジェクトを作成
npx create-react-app my-glen-app
cd my-glen-app

# Glen ID SDK と React コンポーネントをコピー
cp examples/sdk/javascript/glen-id-sdk.js src/
cp examples/react-integration/src/components/GlenAuth.jsx src/components/

# App.js を更新
```

```jsx
import React from 'react';
import {
  GlenIdProvider,
  useGlenId,
  LoginButton,
  LogoutButton,
  UserProfile,
  ProtectedRoute
} from './components/GlenAuth';

const config = {
  baseUrl: 'https://glen.dqx0.com',
  clientId: 'my-react-app',
  scopes: ['read', 'write']
};

function App() {
  return (
    <GlenIdProvider config={config}>
      <div className="App">
        <header>
          <h1>My App</h1>
          <AuthSection />
        </header>
        <main>
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        </main>
      </div>
    </GlenIdProvider>
  );
}

function AuthSection() {
  const { isAuthenticated } = useGlenId();
  
  return isAuthenticated ? (
    <div>
      <UserProfile />
      <LogoutButton />
    </div>
  ) : (
    <LoginButton />
  );
}

function Dashboard() {
  return <div>保護されたコンテンツ</div>;
}

export default App;
```

### Flask (Python) 統合

```bash
# 仮想環境を作成
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 依存関係をインストール
pip install -r examples/python-flask/requirements.txt

# 環境変数を設定
export GLEN_ID_API_KEY="your-api-key-here"
export SECRET_KEY="your-flask-secret-key"

# アプリケーションを起動
python examples/python-flask/app.py
```

アプリケーションは `http://localhost:5000` で起動します。

## 📚 詳細な使用方法

### JavaScript SDK API

#### 初期化

```javascript
const glenId = new GlenIdSDK({
    baseUrl: 'https://glen.dqx0.com',           // Glen ID Platform URL
    apiBaseUrl: 'https://api.glen.dqx0.com/api/v1', // API URL
    clientId: 'your-app-id',                    // アプリケーションID
    redirectUri: 'https://yourapp.com/callback', // コールバックURL
    scopes: ['read', 'write'],                  // 要求するスコープ
    debug: true                                 // デバッグモード
});
```

#### 認証

```javascript
// ログイン開始
glenId.login();

// ログアウト
glenId.logout();

// 認証状態確認
const isAuth = glenId.isAuthenticated();

// ユーザー情報取得
const user = await glenId.fetchUserInfo();

// トークン取得
const token = glenId.getToken();
```

#### API呼び出し

```javascript
// 保護されたAPIを呼び出し
const response = await glenId.apiCall('/api/protected');
const data = await response.json();

// POST リクエスト
const response = await glenId.apiCall('/api/data', {
    method: 'POST',
    body: JSON.stringify({ key: 'value' })
});
```

#### イベントハンドリング

```javascript
// ログイン成功
glenId.on('loginSuccess', ({ token }) => {
    console.log('ログインしました');
});

// ログアウト
glenId.on('loggedOut', () => {
    console.log('ログアウトしました');
});

// トークン期限切れ
glenId.on('tokenExpired', () => {
    console.log('セッションが期限切れです');
});

// エラー
glenId.on('error', (error) => {
    console.error('エラーが発生しました:', error);
});
```

### React フック

#### useGlenId

```javascript
const { 
    user,           // ユーザー情報
    isAuthenticated,// 認証状態
    isLoading,      // 読み込み状態
    error,          // エラー情報
    login,          // ログイン関数
    logout,         // ログアウト関数
    sdk             // SDK インスタンス
} = useGlenId();
```

#### useWebAuthnCredentials

```javascript
const { 
    credentials,    // WebAuthn認証器リスト
    loading,        // 読み込み状態
    refresh         // リスト更新関数
} = useWebAuthnCredentials();
```

#### useSocialAccounts

```javascript
const { 
    accounts,       // ソーシャルアカウントリスト
    loading,        // 読み込み状態
    refresh         // リスト更新関数
} = useSocialAccounts();
```

#### useApiKeys

```javascript
const { 
    tokens,         // APIキーリスト
    loading,        // 読み込み状態
    createToken,    // APIキー作成関数
    refresh         // リスト更新関数
} = useApiKeys();
```

### Flask デコレータ

#### @require_auth

```python
@app.route('/api/protected')
@require_auth(['read'])  # 'read' スコープが必要
def protected_endpoint():
    user = request.glen_user      # ユーザー情報
    scopes = request.glen_scopes  # ユーザーのスコープ
    return jsonify({'user': user})
```

#### @require_scope

```python
@app.route('/api/admin')
@require_auth(['read'])
@require_scope('admin')  # 'admin' スコープが必要
def admin_endpoint():
    return jsonify({'message': '管理者のみアクセス可能'})
```

## 🔧 カスタマイズ

### カスタム認証フロー

```javascript
class CustomGlenAuth extends GlenIdSDK {
    async customLogin() {
        // カスタムログインロジック
        const result = await this.login({
            scopes: ['read', 'write', 'custom'],
            redirectUri: '/custom-callback'
        });
        
        // 追加処理
        await this.trackLoginEvent();
        
        return result;
    }
    
    async trackLoginEvent() {
        // ログインイベントを追跡
        await this.apiCall('/api/analytics/login', {
            method: 'POST'
        });
    }
}
```

### カスタムエラーハンドリング

```javascript
glenId.on('error', (error) => {
    // カスタムエラー処理
    switch (error.type) {
        case 'network':
            showNetworkError();
            break;
        case 'auth':
            redirectToLogin();
            break;
        default:
            showGenericError(error.message);
    }
});
```

### カスタムUI コンポーネント

```jsx
function CustomLoginButton() {
    const { login, isLoading } = useGlenId();
    
    return (
        <button 
            onClick={login}
            disabled={isLoading}
            className="my-custom-button"
        >
            {isLoading ? (
                <Spinner />
            ) : (
                <>
                    <GlenIcon />
                    Glen ID でログイン
                </>
            )}
        </button>
    );
}
```

## 🧪 テスト

### JavaScript SDK テスト

```javascript
// Jest テスト例
describe('GlenIdSDK', () => {
    let sdk;
    
    beforeEach(() => {
        sdk = new GlenIdSDK({
            baseUrl: 'https://test.glen.dqx0.com',
            debug: false
        });
    });
    
    test('should initialize correctly', () => {
        expect(sdk.config.baseUrl).toBe('https://test.glen.dqx0.com');
    });
    
    test('should handle login', async () => {
        const loginSpy = jest.spyOn(sdk, 'login');
        sdk.login();
        expect(loginSpy).toHaveBeenCalled();
    });
});
```

### Flask テスト

```python
# pytest テスト例
import pytest
from app import app, glen_client

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_public_endpoint(client):
    """公開エンドポイントのテスト"""
    response = client.get('/api/public')
    assert response.status_code == 200
    assert response.json['authenticated'] == False

def test_protected_endpoint_without_auth(client):
    """認証なしでの保護されたエンドポイントのテスト"""
    response = client.get('/api/protected')
    assert response.status_code == 401

def test_protected_endpoint_with_auth(client, mock_token):
    """認証ありでの保護されたエンドポイントのテスト"""
    headers = {'Authorization': f'Bearer {mock_token}'}
    response = client.get('/api/protected', headers=headers)
    assert response.status_code == 200
    assert response.json['authenticated'] == True
```

## 🚀 デプロイ

### Vercel (React)

```json
{
  "name": "my-glen-app",
  "version": "2",
  "builds": [
    {
      "src": "package.json",
      "use": "@vercel/static-build",
      "config": { "distDir": "build" }
    }
  ],
  "routes": [
    {
      "src": "/auth/callback",
      "dest": "/index.html"
    },
    {
      "src": "/(.*)",
      "dest": "/index.html"
    }
  ]
}
```

### Heroku (Flask)

```yaml
# Procfile
web: gunicorn app:app

# runtime.txt
python-3.11.0

# 環境変数設定
heroku config:set GLEN_ID_API_KEY=your-api-key
heroku config:set SECRET_KEY=your-secret-key
```

### Docker

```dockerfile
# Dockerfile (Flask)
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

## 📖 その他のリソース

- [Glen ID Platform API ドキュメント](https://api.glen.dqx0.com/docs)
- [外部サービス連携ガイド](../docs/external-service-integration.md)
- [GitHub リポジトリ](https://github.com/dqx0/glen)

## 🆘 サポート

質問やバグ報告は以下で受け付けています：

- [GitHub Issues](https://github.com/dqx0/glen/issues)
- [Discord サーバー](https://discord.gg/glen-id)
- メール: support@glen.dqx0.com

## 📄 ライセンス

MIT License - 詳細は [LICENSE](../LICENSE) ファイルを参照してください。