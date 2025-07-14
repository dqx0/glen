# Glen ID Platform - デプロイメントガイド

## 概要

Glen ID Platformの本番環境デプロイメントガイドです。Terraformを使用したインフラストラクチャ構築とKubernetesを使用したアプリケーションデプロイメントについて説明します。

## 前提条件

### 必要なツール

- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Terraform](https://www.terraform.io/downloads)
- [Docker](https://docs.docker.com/get-docker/)

### GCPプロジェクトの準備

1. GCPプロジェクトの作成
2. 必要なAPIの有効化
3. サービスアカウントの作成
4. 請求先アカウントの設定

## デプロイメント手順

### 1. 初期設定

```bash
# リポジトリのクローン
git clone <repository-url>
cd glen

# GCP認証
gcloud auth login
gcloud config set project glen-id-platform

# 必要な権限の確認
gcloud auth list
```

### 2. シークレットの設定

**方法1: 自動生成スクリプト（推奨）**

```bash
# シークレット自動生成スクリプトの実行
./scripts/generate-secrets.sh
```

**方法2: インタラクティブ設定**

```bash
# シークレット設定スクリプトの実行
./scripts/setup-secrets.sh
```

**自動生成スクリプト**は以下を実行します：
- セキュアなパスワード・シークレットの自動生成
- パスワード強度チェック
- 環境変数ファイル（.env.secrets）の生成
- Kubernetes secrets YAML（k8s-secrets.yaml）の生成
- terraform.tfvarsファイルの生成

**インタラクティブスクリプト**は以下を実行します：
- データベースパスワード、JWTシークレット等の入力（自動生成オプション付き）
- Kubernetesシークレットの作成
- terraform.tfvarsファイルの生成
- GitHub Secretsの設定ガイド表示

### 3. Terraformでインフラストラクチャのデプロイ

```bash
# Terraformデプロイスクリプトの実行
./scripts/deploy.sh terraform
```

このステップで以下のリソースが作成されます：
- GKEクラスタ
- Cloud SQL (PostgreSQL)
- Cloud Memorystore (Redis)
- VPCネットワーク
- ロードバランサー
- Secret Manager

### 4. Kubernetesアプリケーションのデプロイ

```bash
# Kubernetesデプロイスクリプトの実行
./scripts/deploy.sh kubernetes
```

このステップで以下がデプロイされます：
- 認証サービス
- ユーザーサービス
- ソーシャルサービス
- APIゲートウェイ
- フロントエンド

### 5. 全体デプロイ（推奨）

```bash
# 全体デプロイスクリプトの実行
./scripts/deploy.sh all
```

## GitHub Actions設定

### 必要なSecrets

GitHubリポジトリのSettings > Secrets and variables > Actionsで以下を設定：

```
# Docker Hub認証
DOCKER_HUB_USERNAME: [あなたのDocker Hubユーザー名]
DOCKER_HUB_PASSWORD: [あなたのDocker Hubパスワード/トークン]

# GCP認証（Kubernetesデプロイ用）
GCP_PROJECT_ID: glen-id-platform
GCP_SA_KEY: [サービスアカウントJSONキー]
```

### CI/CDパイプライン

- `main`ブランチへのpush時に自動デプロイ
- プルリクエスト時にテスト実行
- セキュリティスキャンの定期実行

## 運用管理

### モニタリング

```bash
# システム状態確認
./scripts/monitor.sh status

# ログ確認
./scripts/monitor.sh logs

# ヘルスチェック
./scripts/monitor.sh health

# リソース使用量確認
./scripts/monitor.sh metrics

# トラブルシューティング
./scripts/monitor.sh troubleshoot
```

### スケーリング

```bash
# Podの手動スケーリング
kubectl scale deployment glen-auth-service --replicas=3 -n glen-system

# オートスケーリング設定
kubectl autoscale deployment glen-auth-service --cpu-percent=70 --min=1 --max=5 -n glen-system
```

### 更新

```bash
# アプリケーションの更新（CI/CDパイプラインを使用）
git push origin main

# 手動でのイメージ更新
kubectl set image deployment/glen-auth-service auth-service=gcr.io/glen-id-platform/glen-auth-service:new-tag -n glen-system
```

## トラブルシューティング

### よくある問題

1. **Podが起動しない**
   ```bash
   kubectl describe pod <pod-name> -n glen-system
   kubectl logs <pod-name> -n glen-system
   ```

2. **データベース接続エラー**
   - Cloud SQLの認証情報確認
   - ネットワーク設定確認
   - シークレットの設定確認

3. **外部アクセスできない**
   - Ingressの設定確認
   - SSL証明書の状態確認
   - DNS設定確認

### ログの確認

```bash
# 特定のサービスのログ
kubectl logs -n glen-system -l app=glen-auth-service -f

# 全サービスのログ
./scripts/monitor.sh logs
```

## セキュリティ

### シークレット管理

- すべてのシークレットはKubernetes SecretsまたはGoogle Secret Managerで管理
- ローカル環境でのシークレットファイルは`.gitignore`に追加
- 定期的なシークレットローテーション

### ネットワークセキュリティ

- VPCネットワークでの分離
- ファイアウォールルールの設定
- SSL/TLS証明書の自動更新

## バックアップ・復旧

### データベースバックアップ

```bash
# 手動バックアップ
gcloud sql backups create --instance=glen-postgres

# バックアップの確認
gcloud sql backups list --instance=glen-postgres
```

### 復旧手順

1. データベースの復旧
2. アプリケーションの再デプロイ
3. 設定の復元

## コスト最適化

### 現在の構成（コスト最適化済み）

- GKE: e2-micro インスタンス
- Cloud SQL: db-f1-micro インスタンス
- Pod数: 各サービス1レプリカ
- ストレージ: 最小構成

### 使用量監視

```bash
# リソース使用量の確認
./scripts/monitor.sh metrics

# GCPコンソールでの請求情報確認
gcloud billing accounts list
```

## 参考資料

- [CI/CD設計・デプロイ計画書](docs/cicd-deployment-plan.md)
- [Terraformドキュメント](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Kubernetesドキュメント](https://kubernetes.io/docs/)
- [GKEドキュメント](https://cloud.google.com/kubernetes-engine/docs)

## サポート

問題が発生した場合：

1. モニタリングスクリプトでの状態確認
2. ログの確認
3. GitHub Issues での報告
4. 緊急時の連絡先への連絡