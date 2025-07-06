# Docker環境ガイド

Glen ID PlatformのDocker環境セットアップと使用方法

## 🚀 クイックスタート

### 1. 初回セットアップ
```bash
# 全て自動でセットアップ
make quickstart

# または手動で
make dev          # PostgreSQL + Redis起動
make setup-deps   # Go依存関係ダウンロード
make docker-build # Dockerイメージビルド
```

### 2. 開発環境起動
```bash
# フルスタック起動（推奨）
make fullstack

# または段階的に
make dev          # データベース起動
make dev-services # Goサービス起動
```

### 3. 停止
```bash
# フルスタック停止
make fullstack-stop

# または個別に
make dev-services-stop  # Goサービス停止
make dev-stop          # データベース停止
```

---

## 🛠️ 開発環境詳細

### データベース環境
```bash
make dev         # PostgreSQL + Redis起動
make dev-stop    # 停止
make dev-logs    # ログ表示
make dev-status  # ステータス確認
make dev-restart # 再起動
```

**接続情報:**
- **PostgreSQL**: `localhost:5432`
  - Database: `glen_dev`
  - User: `glen_dev`
  - Password: `glen_dev_pass`
- **Redis**: `localhost:6379`

### Goサービス起動
```bash
make dev-services      # 全サービス起動
make dev-services-stop # 全サービス停止
```

**サービス一覧:**
- **API Gateway**: `http://localhost:8080`
- **User Service**: `http://localhost:8082`
- **Auth Service**: `http://localhost:8081`
- **Social Service**: `http://localhost:8083`

---

## 🧪 テスト環境

### ユニットテスト
```bash
make test-unit      # 全ユニットテスト実行
make test-coverage  # カバレッジ付きテスト
```

### E2Eテスト
```bash
# ワンショット実行（推奨）
make test-e2e

# 永続環境で開発
make test-e2e-up    # E2E環境起動
# 手動テスト...
make test-e2e-down  # E2E環境停止

# ログ確認
make test-e2e-logs
```

---

## 🐳 Docker管理

### イメージビルド
```bash
make docker-build          # 順次ビルド
make docker-build-parallel # 並列ビルド（高速）
```

### クリーンアップ
```bash
make clean              # Go成果物削除
make docker-clean       # Dockerイメージ削除
make docker-prune       # Dockerシステム全体クリーンアップ
make clean-all          # 全クリーンアップ
```

---

## 📋 使用例

### 一般的な開発フロー
```bash
# 1. 初回セットアップ
make quickstart

# 2. 開発開始
make fullstack

# 3. コード変更後
make test-unit

# 4. 統合確認
make test-e2e

# 5. 開発終了
make fullstack-stop
```

### トラブルシューティング
```bash
# ポート競合などの問題
make fullstack-stop
make clean-all
make docker-prune

# 再起動
make quickstart
make fullstack
```

### CI/CDでの使用
```bash
# 自動テスト
make docker-build
make test-unit
make test-e2e
```

---

## 🔧 カスタマイズ

### 環境変数
開発時に独自の設定を使用したい場合：

```bash
# .env.local を作成
DB_HOST=custom-db
DB_PASSWORD=custom-pass

# サービス起動時に読み込み
source .env.local && make dev-services
```

### Dockerイメージタグ
```bash
# カスタムタグでビルド
docker build -t glen/auth-service:v1.0.0 services/auth-service
```

---

## 📊 モニタリング

### ヘルスチェック
全サービスに `/health` エンドポイントが実装済み：

```bash
curl http://localhost:8080/health  # API Gateway
curl http://localhost:8081/health  # Auth Service
curl http://localhost:8082/health  # User Service
curl http://localhost:8083/health  # Social Service
```

### ログ確認
```bash
make dev-logs       # 開発環境ログ
make test-e2e-logs  # E2Eテスト環境ログ

# 個別ログ
docker-compose -f infrastructure/docker/docker-compose.dev.yml logs postgres
```

---

## 🚨 注意事項

1. **ポート使用**:
   - 8080-8083: Goサービス
   - 5432: PostgreSQL
   - 6379: Redis

2. **データ永続化**:
   - 開発データは Docker volume に保存
   - `make clean-all` では削除されません

3. **パフォーマンス**:
   - `make docker-build-parallel` が高速
   - 初回ビルドは時間がかかります

4. **セキュリティ**:
   - 開発環境のパスワードは本番で使用禁止
   - テスト用OAuth2設定のみ

---

## 🆘 ヘルプ

```bash
make help  # 全コマンド一覧表示
```

問題がある場合は、まず `make clean-all` と `make docker-prune` を実行してください。