# Auth Service

Glen ID Platform の認証サービス。JWT、Refresh Token、API Key による認証機能を提供。

## 機能

- **JWT 認証**: RS256 署名による 15 分間有効なアクセストークン
- **Refresh Token**: 30 日間有効なリフレッシュトークン
- **API Key**: 無期限で使用可能な API キー
- **トークン管理**: 作成、無効化、一覧表示
- **セキュリティ**: bcrypt によるトークンハッシュ化

## API エンドポイント

### 認証

- `POST /api/v1/auth/login` - ユーザーログイン
- `POST /api/v1/auth/refresh` - トークンリフレッシュ
- `POST /api/v1/auth/revoke` - トークン無効化

### API キー管理

- `POST /api/v1/auth/api-keys` - API キー作成
- `GET /api/v1/auth/tokens?user_id=xxx` - ユーザーのトークン一覧

### 内部 API

- `POST /api/v1/auth/validate-api-key` - API キー検証

### ヘルスチェック

- `GET /health` - サービスヘルスチェック

## 環境変数

| 変数名 | 説明 | デフォルト値 |
|-------|------|-------------|
| `PORT` | サーバーポート | `8081` |
| `DATABASE_URL` | PostgreSQL 接続文字列 | `postgres://glen_user:glen_password@localhost:5432/glen_auth?sslmode=disable` |

## 開発

### テスト実行

```bash
go test ./internal/...
```

### ローカル実行

```bash
# データベース起動（Docker Compose 使用時）
docker-compose up -d postgres

# サービス起動
go run ./cmd/server/main.go
```

### Docker ビルド

```bash
docker build -t glen-auth-service .
```

## データベーススキーマ

```sql
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_type TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    name TEXT,
    scopes TEXT, -- JSON文字列として保存
    expires_at DATETIME,
    last_used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## アーキテクチャ

```
├── cmd/server/          # アプリケーションエントリーポイント
├── internal/
│   ├── models/          # ドメインモデル
│   ├── repository/      # データアクセス層
│   ├── service/         # ビジネスロジック層
│   └── handlers/        # HTTP ハンドラー層
├── Dockerfile
└── README.md
```

## セキュリティ考慮事項

- トークンは bcrypt でハッシュ化して保存
- JWT は RS256 署名を使用
- API キーは一度だけ表示（作成時のみ）
- 期限切れトークンの自動削除機能
- HTTPS 使用を強く推奨