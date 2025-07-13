# Glen OAuth2 Sample App

Glen ID Platform の OAuth2 統合をテストするためのシンプルなサンプルアプリケーションです。

## 📋 概要

このサンプルアプリは以下の機能を提供します：

- OAuth2 Authorization Code Flow
- PKCE (Proof Key for Code Exchange) サポート
- アクセストークンとリフレッシュトークンの管理
- トークンの無効化
- 保護されたAPIエンドポイントのテスト
- ログ機能とエラーハンドリング

## 🚀 セットアップ

### 1. 依存関係のインストール

```bash
cd /path/to/glen/examples/oauth2-sample-app
npm install
```

### 2. Glen ID Platform での OAuth2 クライアント作成

Glen ID Platform のダッシュボードで新しい OAuth2 クライアントを作成します：

1. **Client Name**: `OAuth2 Sample App`
2. **Description**: `Glen OAuth2 integration sample application`
3. **Redirect URIs**: `http://localhost:3000/callback`
4. **Scopes**: `read write`
5. **Client Type**: Public または Confidential

作成後、以下の情報を控えておきます：
- Client ID
- Client Secret (Confidential クライアントの場合)

### 3. アプリケーションの起動

```bash
npm start
```

アプリケーションは `http://localhost:3000` で起動します。

## 📝 使用方法

### 1. 設定

ブラウザでアプリケーションを開き、設定セクションで以下を入力：

- **Glen API Base URL**: `https://api.glen.dqx0.com/api/v1` (本番) または `http://localhost:3001/api/v1` (開発)
- **Frontend Base URL**: `https://glen.dqx0.com` (本番) または `http://localhost:3000` (開発)
- **Client ID**: 作成した OAuth2 クライアントの ID
- **Client Secret**: Confidential クライアントの場合のみ入力
- **Redirect URI**: `http://localhost:3000/callback`
- **Scope**: `read write`

「設定を保存」ボタンをクリックして設定を保存します。

### 2. OAuth2 認証テスト

#### 通常の OAuth2 フロー

「Glen ID でログイン」ボタンをクリックして OAuth2 認証を開始します。

#### PKCE フロー

「PKCE でログイン」ボタンをクリックして PKCE 付きの OAuth2 認証を開始します。Public クライアントの場合は推奨です。

### 3. 認証後の操作

認証が成功すると以下の操作が可能になります：

- **トークン更新**: リフレッシュトークンを使用してアクセストークンを更新
- **トークン無効化**: 現在のアクセストークンを無効化
- **API テスト**: 保護されたAPIエンドポイントを呼び出し
- **ログアウト**: ローカルセッションをクリア

## 🔧 技術詳細

### OAuth2 フロー

1. **Authorization Request**: ユーザーを Glen ID Platform の認証ページにリダイレクト
2. **Authorization Grant**: ユーザーが認証し、認証コードを取得
3. **Access Token Request**: 認証コードをアクセストークンに交換
4. **Protected Resource Access**: アクセストークンを使用してAPIを呼び出し

### PKCE サポート

Public クライアント向けのセキュリティ強化として PKCE をサポート：

- `code_verifier`: ランダムな128文字の文字列
- `code_challenge`: code_verifier のSHA256ハッシュをBase64URL エンコード
- `code_challenge_method`: `S256`

### エラーハンドリング

- OAuth2 標準エラーレスポンスの処理
- ネットワークエラーの適切な処理
- CSRF保護のための state パラメータ検証

## 📁 ファイル構成

```
oauth2-sample-app/
├── index.html          # メインのHTMLファイル（SPA）
├── server.js           # Express.js サーバー
├── package.json        # npm設定
└── README.md          # このファイル
```

## 🌐 エンドポイント

- `/` - メインアプリケーション
- `/callback` - OAuth2 コールバック
- `/health` - ヘルスチェック

## 🔐 セキュリティ考慮事項

- State パラメータによるCSRF保護
- PKCE による Public クライアントのセキュリティ強化
- アクセストークンのセキュアな保存（メモリ内）
- HTTPS 通信の推奨（本番環境）

## 🚨 トラブルシューティング

### よくある問題

#### 1. "Client ID が設定されていません"

**解決方法**: 設定セクションで有効な Client ID を入力し、「設定を保存」をクリック

#### 2. "invalid_client" エラー

**解決方法**: 
- Client ID が正しいか確認
- Client Secret が必要な場合は正しく設定されているか確認
- Redirect URI が Glen ID Platform で設定されているものと一致するか確認

#### 3. "redirect_uri_mismatch" エラー

**解決方法**: Glen ID Platform で設定した Redirect URI と アプリの設定が一致するか確認

#### 4. CORS エラー

**解決方法**: 
- 開発環境では `http://localhost:3000` を使用
- 本番環境では適切なドメインを設定

### デバッグ

アプリケーション内のログセクションでリアルタイムでログを確認できます。ブラウザの開発者ツールのコンソールでも詳細なログを確認可能です。

## 📞 サポート

問題が発生した場合は、Glen ID Platform のドキュメントを参照するか、サポートチームにお問い合わせください。