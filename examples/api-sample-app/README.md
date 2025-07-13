# Glen API Sample App

Glen ID Platform の API 機能をテストするためのサンプルアプリケーションです。

## 機能

### 認証
- **API Key 認証**: API Key を使用した認証
- **API Key テスト**: 設定した API Key の有効性を検証

### API エンドポイント

#### ユーザー管理
- **GET /users/me**: 現在認証されているユーザーの情報を取得

#### 認証・トークン管理
- **GET /auth/tokens**: ユーザーのアクティブなトークン一覧を取得
- **POST /auth/api-keys**: 新しい API Key を作成
- **POST /auth/revoke**: 指定したトークンを無効化
- **POST /auth/validate-api-key**: API Key の有効性を検証

#### ソーシャルログイン
- **GET /social/providers**: 利用可能なソーシャルログインプロバイダーを取得

#### OAuth2
- **GET /oauth2/clients**: OAuth2 クライアント一覧を取得

## 使用方法

### 1. サーバー起動
Glen ID Platform のサービスが起動していることを確認してください：
- API Gateway: http://localhost:8080
- User Service: http://localhost:8082
- Auth Service: http://localhost:8081
- Social Service: http://localhost:8083

### 2. アプリケーション起動
```bash
# ローカルサーバーで起動（例：Python）
cd /path/to/glen/examples/api-sample-app
python3 -m http.server 3001

# または任意のHTTPサーバーで index.html を開く
```

### 3. API Key の取得
API Key を取得する方法：

1. **Glen ID フロントエンドでログイン**
   - http://localhost:5173 でログイン
   - ダッシュボードで API Key を作成

2. **API Sample App で直接作成**
   - User ID を指定して API Key を作成
   - 作成された API Key をコピー

### 4. API Key の設定
1. API Sample App を開く
2. 「設定」セクションで API Key を入力
3. 「設定を保存」をクリック
4. 「API Key をテスト」をクリックして認証

### 5. API のテスト
認証成功後、各 API エンドポイントをテストできます：
- エンドポイントカードをクリックして詳細を表示
- 必要なパラメータを入力
- 「実行」ボタンをクリック
- 結果がログとカード内に表示されます

## API Key の形式

API Key は以下の形式で Authorization ヘッダーに設定されます：
```
Authorization: ApiKey your-api-key-here
```

## エラー処理

- 認証エラー: API Key が無効または期限切れ
- リクエストエラー: パラメータ不足や形式エラー
- サーバーエラー: サービスの起動状況を確認

## 設定

### API Base URL
デフォルト: `http://localhost:8080/api/v1`

本番環境では `https://api.glen.dqx0.com/api/v1` に変更してください。

### ローカルストレージ
設定は自動的にローカルストレージに保存されます：
- API Base URL
- API Key

## セキュリティ

⚠️ **重要**: API Key は機密情報です。
- 本番環境では HTTPS を使用
- API Key をコードに直接埋め込まない
- 定期的に API Key をローテーション
- 不要な API Key は削除

## トラブルシューティング

### CORS エラー
API Gateway で CORS が正しく設定されているか確認してください。

### 404 エラー
- API Gateway が起動しているか確認
- エンドポイントのパスが正しいか確認

### 認証エラー
- API Key が正しく設定されているか確認
- API Key の有効期限を確認
- API Key の形式（`ApiKey ` プレフィックス）を確認

## 開発

このサンプルアプリは教育目的で作成されています。実際のアプリケーション開発では：

1. **適切なエラーハンドリング**を実装
2. **レート制限**を考慮
3. **セキュアな認証情報管理**を実装
4. **本番用の設定管理**を実装