# E2Eテスト

Glen ID Platformの統合テスト（End-to-End Tests）

## 概要

このディレクトリには、全サービスが連携して動作することを確認するE2Eテストが含まれています。

## テストシナリオ

### 1. ユーザー登録・認証フロー
- ユーザー登録 (user-service)
- JWT認証 (auth-service)
- API Gatewayを通じたアクセス

### 2. ソーシャルログインフロー
- OAuth2認証開始 (social-service)
- コールバック処理
- ユーザー作成または既存ユーザーとの紐づけ
- JWTトークン発行

### 3. APIキー管理フロー
- APIキー作成
- APIキーを使用したAPI呼び出し
- APIキーの無効化

## 実行環境

- PostgreSQLデータベース
- 全マイクロサービスの起動
- API Gatewayの起動

## 実行方法

```bash
# テスト環境起動
make dev

# E2Eテスト実行
make test-e2e

# テスト環境停止
make dev-stop
```

## テストデータ

テスト実行時には専用のテストデータベースを使用し、テスト終了後にクリーンアップされます。