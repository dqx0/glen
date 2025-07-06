# Glen - WebAuthn-Based Identity Service

マイクロサービスベースのID基盤

## アーキテクチャ

### マイクロサービス構成
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │  API Gateway    │    │  Auth Service   │
│   (React)       │◄──►│                 │◄──►│  (JWT/OAuth)    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                ▲                        ▲
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  User Service   │    │   PostgreSQL    │    │   Shared Libs   │
│  (CRUD/WebAuthn)│◄──►│   (Cloud SQL)   │    │   (Types/Utils) │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 認証フロー設計
```
1. WebAuthn (Primary)    2. Social Login      3. Password (Fallback)
   ┌─────────────┐          ┌─────────────┐        ┌─────────────┐
   │  Biometric  │          │ Google/GH/  │        │  Username/  │
   │  Security   │   OR     │ Discord     │   OR   │  Password   │
   │  Key        │          │ OAuth       │        │             │
   └─────────────┘          └─────────────┘        └─────────────┘
           │                        │                      │
           └────────────────────────┼──────────────────────┘
                                    ▼
                           ┌─────────────────┐
                           │   JWT Token     │
                           │   (+ Refresh)   │
                           └─────────────────┘
```

### ディレクトリ構成

```
glen/
├── services/
│   ├── auth-service/        # 認証サービス (WebAuthn, JWT)
│   ├── user-service/        # ユーザー管理サービス
│   └── api-gateway/         # API Gateway
├── frontend/                # React フロントエンド
├── shared/                  # 共通ライブラリ
├── infrastructure/          # K8s, Docker設定
└── scripts/                 # 開発・デプロイスクリプト
```

## 技術スタック

- **Backend**: Go + PostgreSQL
- **Frontend**: React + TypeScript
- **Infrastructure**: GCP + K8s
- **Testing**: Go標準テスト + testify
- **CI/CD**: GitHub Actions

## 開発環境セットアップ

```bash
# 各サービスのGoモジュール初期化
cd services/auth-service && go mod init github.com/dqx0/glen/auth-service
cd services/user-service && go mod init github.com/dqx0/glen/user-service
cd services/api-gateway && go mod init github.com/dqx0/glen/api-gateway

# 共通ライブラリ
cd shared && go mod init github.com/dqx0/glen/shared

# テスト実行
make test

# ローカル環境起動
make dev
```