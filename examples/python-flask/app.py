"""
Glen ID Platform Flask Integration Example

このサンプルアプリケーションは、PythonのFlaskフレームワークで
Glen ID Platform と連携する方法を示しています。

機能:
- JWT トークンベース認証
- APIキーによる認証
- セッション管理
- ユーザー情報取得
- 保護されたエンドポイント
"""

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import requests
import os
import functools
import jwt
from datetime import datetime, timedelta
import logging

# Flask アプリケーションの設定
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Glen ID Platform の設定
GLEN_ID_CONFIG = {
    'base_url': 'https://glen.dqx0.com',
    'api_base_url': 'https://api.glen.dqx0.com/api/v1',
    'api_key': os.environ.get('GLEN_ID_API_KEY'),
    'client_id': 'flask-example-app',
    'redirect_uri': 'http://localhost:5000/auth/callback'
}

# ログ設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GlenIdClient:
    """Glen ID Platform API クライアント"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        if config.get('api_key'):
            self.session.headers.update({
                'X-API-Key': config['api_key'],
                'Content-Type': 'application/json'
            })
    
    def validate_token(self, token, required_scopes=None):
        """JWTトークンを検証"""
        try:
            payload = {
                'token': token
            }
            if required_scopes:
                payload['required_scopes'] = required_scopes
            
            response = self.session.post(
                f"{self.config['api_base_url']}/external/validate-session",
                json=payload
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Token validation failed: {e}")
            return None
    
    def get_user_info(self, user_id):
        """ユーザー情報を取得"""
        try:
            response = self.session.get(
                f"{self.config['api_base_url']}/users/{user_id}"
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to get user info: {e}")
            return None
    
    def get_user_info_by_token(self, token):
        """JWTトークンからユーザー情報を取得"""
        validation_result = self.validate_token(token)
        if validation_result and validation_result.get('valid'):
            return validation_result.get('user')
        return None

# Glen ID クライアントのインスタンス
glen_client = GlenIdClient(GLEN_ID_CONFIG)

def require_auth(scopes=None):
    """認証が必要なエンドポイントのデコレータ"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Authorizationヘッダーからトークンを取得
            auth_header = request.headers.get('Authorization', '')
            token = None
            
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
            elif 'glen_id_token' in session:
                token = session['glen_id_token']
            
            if not token:
                return jsonify({'error': 'Token required'}), 401
            
            # トークンを検証
            validation_result = glen_client.validate_token(token, scopes)
            if not validation_result or not validation_result.get('valid'):
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # リクエストオブジェクトにユーザー情報を添付
            request.glen_user = validation_result.get('user')
            request.glen_scopes = validation_result.get('scopes', [])
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_scope(required_scope):
    """特定のスコープが必要なエンドポイントのデコレータ"""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user_scopes = getattr(request, 'glen_scopes', [])
            if required_scope not in user_scopes:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_scope': required_scope
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# HTML テンプレート
HOME_TEMPLATE = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Glen ID Flask Integration Example</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #f8fafc;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid #e2e8f0;
        }
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background-color: #6366f1;
            color: white;
            text-decoration: none;
            border-radius: 0.375rem;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            margin: 0.5rem;
        }
        .btn:hover {
            background-color: #4f46e5;
        }
        .btn-secondary {
            background-color: #64748b;
        }
        .btn-secondary:hover {
            background-color: #475569;
        }
        .user-info {
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 1rem;
            border-radius: 0.375rem;
            margin: 1rem 0;
        }
        .api-section {
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #e2e8f0;
        }
        .endpoint {
            background-color: #f8fafc;
            padding: 1rem;
            border-radius: 0.375rem;
            margin: 0.5rem 0;
            border-left: 4px solid #6366f1;
        }
        .method {
            font-weight: bold;
            color: #6366f1;
        }
        pre {
            background-color: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.375rem;
            overflow-x: auto;
        }
        .error {
            background-color: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 1rem;
            border-radius: 0.375rem;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Glen ID Flask Integration</h1>
            <p>Flask アプリケーションでの Glen ID Platform 統合例</p>
        </div>

        {% if user %}
            <div class="user-info">
                <h3>👤 ログイン中</h3>
                <p><strong>ユーザー名:</strong> {{ user.username }}</p>
                <p><strong>メール:</strong> {{ user.email }}</p>
                <p><strong>ユーザーID:</strong> {{ user.id }}</p>
                <a href="{{ url_for('logout') }}" class="btn btn-secondary">ログアウト</a>
            </div>
        {% else %}
            <div>
                <h3>ログインが必要です</h3>
                <p>Glen ID Platform で認証してください。</p>
                <a href="{{ url_for('login') }}" class="btn">Glen ID でログイン</a>
            </div>
        {% endif %}

        <div class="api-section">
            <h3>📡 API エンドポイント</h3>
            
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/public</code>
                <p>認証不要の公開エンドポイント</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/protected</code>
                <p>認証が必要な保護されたエンドポイント</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/admin</code>
                <p>管理者権限が必要なエンドポイント</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/user/profile</code>
                <p>ユーザー情報を取得</p>
            </div>

            {% if user %}
            <h4>🧪 API テスト</h4>
            <p>以下のコマンドでAPIをテストできます：</p>
            <pre><code># 保護されたエンドポイント
curl -H "Authorization: Bearer YOUR_TOKEN" \\
     http://localhost:5000/api/protected

# ユーザー情報取得
curl -H "Authorization: Bearer YOUR_TOKEN" \\
     http://localhost:5000/api/user/profile</code></pre>
            {% endif %}
        </div>

        {% if error %}
        <div class="error">
            <strong>エラー:</strong> {{ error }}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

# ルート定義

@app.route('/')
def home():
    """ホームページ"""
    user = None
    error = request.args.get('error')
    
    # セッションからトークンを取得してユーザー情報を表示
    if 'glen_id_token' in session:
        token = session['glen_id_token']
        user = glen_client.get_user_info_by_token(token)
        if not user:
            # トークンが無効な場合はセッションをクリア
            session.pop('glen_id_token', None)
    
    return render_template_string(HOME_TEMPLATE, user=user, error=error)

@app.route('/auth/login')
def login():
    """Glen ID Platform ログインページにリダイレクト"""
    login_url = f"{GLEN_ID_CONFIG['base_url']}/login?" \
                f"redirect_uri={GLEN_ID_CONFIG['redirect_uri']}&" \
                f"client_id={GLEN_ID_CONFIG['client_id']}"
    
    logger.info(f"Redirecting to login: {login_url}")
    return redirect(login_url)

@app.route('/auth/callback')
def auth_callback():
    """Glen ID Platform からのコールバック処理"""
    token = request.args.get('token')
    error = request.args.get('error')
    
    if error:
        logger.error(f"Authentication error: {error}")
        return redirect(url_for('home', error=error))
    
    if not token:
        logger.error("No token received in callback")
        return redirect(url_for('home', error='認証に失敗しました'))
    
    # トークンを検証
    validation_result = glen_client.validate_token(token)
    if not validation_result or not validation_result.get('valid'):
        logger.error("Invalid token received")
        return redirect(url_for('home', error='無効なトークンです'))
    
    # セッションにトークンを保存
    session['glen_id_token'] = token
    logger.info(f"User logged in: {validation_result.get('user', {}).get('username')}")
    
    return redirect(url_for('home'))

@app.route('/auth/logout')
def logout():
    """ログアウト"""
    session.pop('glen_id_token', None)
    logger.info("User logged out")
    
    # Glen ID Platform のログアウトページにリダイレクト
    logout_url = f"{GLEN_ID_CONFIG['base_url']}/logout?" \
                 f"redirect_uri={request.url_root}"
    
    return redirect(logout_url)

# API エンドポイント

@app.route('/api/public')
def api_public():
    """認証不要の公開API"""
    return jsonify({
        'message': '🌍 これは公開エンドポイントです',
        'timestamp': datetime.utcnow().isoformat(),
        'authenticated': False
    })

@app.route('/api/protected')
@require_auth(['read'])
def api_protected():
    """認証が必要な保護されたAPI"""
    return jsonify({
        'message': '🔒 認証されたユーザーのみアクセス可能です',
        'user': request.glen_user,
        'scopes': request.glen_scopes,
        'timestamp': datetime.utcnow().isoformat(),
        'authenticated': True
    })

@app.route('/api/admin')
@require_auth(['admin'])
def api_admin():
    """管理者権限が必要なAPI"""
    return jsonify({
        'message': '👑 管理者のみアクセス可能です',
        'user': request.glen_user,
        'scopes': request.glen_scopes,
        'timestamp': datetime.utcnow().isoformat(),
        'admin': True
    })

@app.route('/api/user/profile')
@require_auth(['read'])
def api_user_profile():
    """ユーザープロフィール情報を取得"""
    user = request.glen_user
    
    # 追加のユーザー情報を Glen ID Platform から取得
    detailed_user = glen_client.get_user_info(user['id'])
    
    return jsonify({
        'profile': detailed_user or user,
        'scopes': request.glen_scopes,
        'retrieved_at': datetime.utcnow().isoformat()
    })

@app.route('/api/write-test')
@require_auth(['write'])
@require_scope('write')
def api_write_test():
    """書き込み権限が必要なAPI"""
    return jsonify({
        'message': '✍️ 書き込み権限でアクセスしました',
        'user': request.glen_user,
        'scopes': request.glen_scopes,
        'timestamp': datetime.utcnow().isoformat(),
        'operation': 'write'
    })

# エラーハンドラー

@app.errorhandler(401)
def unauthorized(error):
    """401エラーハンドラー"""
    return jsonify({
        'error': 'Unauthorized',
        'message': '認証が必要です',
        'login_url': url_for('login', _external=True)
    }), 401

@app.errorhandler(403)
def forbidden(error):
    """403エラーハンドラー"""
    return jsonify({
        'error': 'Forbidden',
        'message': 'この操作を実行する権限がありません'
    }), 403

@app.errorhandler(500)
def internal_error(error):
    """500エラーハンドラー"""
    logger.error(f"Internal error: {error}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'サーバー内部エラーが発生しました'
    }), 500

# ヘルスチェック

@app.route('/health')
def health_check():
    """ヘルスチェックエンドポイント"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'glen_id_config': {
            'base_url': GLEN_ID_CONFIG['base_url'],
            'api_configured': bool(GLEN_ID_CONFIG.get('api_key'))
        }
    })

# デバッグ情報（開発環境のみ）

@app.route('/debug/session')
def debug_session():
    """セッション情報の確認（デバッグ用）"""
    if not app.debug:
        return jsonify({'error': 'Debug mode only'}), 403
    
    return jsonify({
        'session': dict(session),
        'has_token': 'glen_id_token' in session
    })

if __name__ == '__main__':
    # 環境変数の確認
    if not GLEN_ID_CONFIG.get('api_key'):
        print("⚠️  Warning: GLEN_ID_API_KEY environment variable not set")
        print("   Some features may not work properly")
    
    print("🚀 Starting Flask application with Glen ID integration")
    print(f"   Home: http://localhost:5000")
    print(f"   Login: http://localhost:5000/auth/login")
    print(f"   Public API: http://localhost:5000/api/public")
    print(f"   Protected API: http://localhost:5000/api/protected")
    
    # デバッグモードで起動
    app.run(debug=True, host='0.0.0.0', port=5000)