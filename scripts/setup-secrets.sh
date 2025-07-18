#!/bin/bash

# Glen ID Platform - Secret設定スクリプト
# 使用方法: ./setup-secrets.sh

set -e

# 色付きの出力
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ログ関数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Base64エンコード関数
encode_base64() {
    echo -n "$1" | base64 -w 0
}

# セキュアなパスワード生成関数
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# JWTシークレット生成関数
generate_jwt_secret() {
    openssl rand -hex 32
}

# OAuth Client ID生成関数
generate_client_id() {
    openssl rand -hex 16
}

# OAuth Client Secret生成関数
generate_client_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

# シークレット情報の入力
get_secrets() {
    log_info "シークレット情報を設定します"
    echo
    
    # データベースパスワード
    read -p "データベースパスワードを自動生成しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        read -s -p "データベースパスワード: " DB_PASSWORD
        echo
    else
        DB_PASSWORD=$(generate_password 24)
        log_success "データベースパスワードを自動生成しました"
    fi
    
    # JWTシークレット
    read -p "JWTシークレットを自動生成しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        read -s -p "JWTシークレット: " JWT_SECRET
        echo
    else
        JWT_SECRET=$(generate_jwt_secret)
        log_success "JWTシークレットを自動生成しました"
    fi
    
    # OAuth情報
    read -p "OAuth Client ID/Secretを自動生成しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        read -p "OAuth Client ID: " OAUTH_CLIENT_ID
        read -s -p "OAuth Client Secret: " OAUTH_CLIENT_SECRET
        echo
    else
        OAUTH_CLIENT_ID=$(generate_client_id)
        OAUTH_CLIENT_SECRET=$(generate_client_secret)
        log_success "OAuth認証情報を自動生成しました"
    fi
    
    # Google OAuth
    read -p "Google OAuth情報を入力しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        GOOGLE_CLIENT_ID=""
        GOOGLE_CLIENT_SECRET=""
        log_info "Google OAuth情報をスキップしました"
    else
        read -p "Google Client ID: " GOOGLE_CLIENT_ID
        read -s -p "Google Client Secret: " GOOGLE_CLIENT_SECRET
        echo
    fi
    
    # GitHub OAuth
    read -p "GitHub OAuth情報を入力しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        _GITHUB_CLIENT_ID=""
        _GITHUB_CLIENT_SECRET=""
        log_info "GitHub OAuth情報をスキップしました"
    else
        read -p "GitHub Client ID: " _GITHUB_CLIENT_ID
        read -s -p "GitHub Client Secret: " _GITHUB_CLIENT_SECRET
        echo
    fi
    
    # Discord OAuth
    read -p "Discord OAuth情報を入力しますか？ (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        DISCORD_CLIENT_ID=""
        DISCORD_CLIENT_SECRET=""
        log_info "Discord OAuth情報をスキップしました"
    else
        read -p "Discord Client ID: " DISCORD_CLIENT_ID
        read -s -p "Discord Client Secret: " DISCORD_CLIENT_SECRET
        echo
    fi
}

# Kubernetesシークレット作成
create_k8s_secrets() {
    log_info "Kubernetesシークレットを作成中..."
    
    # Namespace作成
    kubectl create namespace glen-system --dry-run=client -o yaml | kubectl apply -f -
    
    # シークレットの作成
    kubectl create secret generic glen-secrets \
        --namespace=glen-system \
        --from-literal=DB_PASSWORD="$DB_PASSWORD" \
        --from-literal=JWT_SECRET="$JWT_SECRET" \
        --from-literal=OAUTH_CLIENT_ID="$OAUTH_CLIENT_ID" \
        --from-literal=OAUTH_CLIENT_SECRET="$OAUTH_CLIENT_SECRET" \
        --from-literal=GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
        --from-literal=GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
        --from-literal=_GITHUB_CLIENT_ID="$_GITHUB_CLIENT_ID" \
        --from-literal=_GITHUB_CLIENT_SECRET="$_GITHUB_CLIENT_SECRET" \
        --from-literal=DISCORD_CLIENT_ID="$DISCORD_CLIENT_ID" \
        --from-literal=DISCORD_CLIENT_SECRET="$DISCORD_CLIENT_SECRET" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_success "Kubernetesシークレット作成完了"
}

# terraform.tfvarsファイル作成
create_terraform_vars() {
    log_info "terraform.tfvarsファイルを作成中..."
    
    cat > infrastructure/terraform/terraform.tfvars << EOF
# GCP Project Configuration
project_id = "glen-id-platform"
region     = "asia-northeast1"
zone       = "asia-northeast1-a"

# Database Configuration
db_password = "$DB_PASSWORD"

# JWT Configuration
jwt_secret = "$JWT_SECRET"

# OAuth Configuration
oauth_client_id     = "$OAUTH_CLIENT_ID"
oauth_client_secret = "$OAUTH_CLIENT_SECRET"

# Environment
environment = "production"

# Domain Configuration
domain     = "glen.dqx0.com"
api_domain = "api.glen.dqx0.com"
EOF
    
    log_success "terraform.tfvarsファイル作成完了"
}

# GitHub Secretsの設定ガイド
show_github_secrets_guide() {
    log_info "GitHub Secretsの設定ガイド"
    echo
    echo "GitHubリポジトリのSettings > Secrets and variables > Actionsで以下のシークレットを設定してください:"
    echo
    echo "GCP_PROJECT_ID: glen-id-platform"
    echo "GCP_SA_KEY: [サービスアカウントキーのJSONファイル内容]"
    echo "DB_PASSWORD: $(encode_base64 "$DB_PASSWORD")"
    echo "JWT_SECRET: $(encode_base64 "$JWT_SECRET")"
    echo "OAUTH_CLIENT_ID: $(encode_base64 "$OAUTH_CLIENT_ID")"
    echo "OAUTH_CLIENT_SECRET: $(encode_base64 "$OAUTH_CLIENT_SECRET")"
    echo
    echo "サービスアカウントキーの作成方法:"
    echo "1. GCP Console > IAM & Admin > Service Accounts"
    echo "2. glen-service-account を選択"
    echo "3. Keys タブ > Add Key > Create new key > JSON"
    echo "4. ダウンロードしたJSONファイルの内容をGCP_SA_KEYに設定"
    echo
}

# 設定ファイルの更新
update_config_files() {
    log_info "設定ファイルを更新中..."
    
    # ConfigMapの更新（必要に応じて）
    # 注意: プライベートIPは実際のデプロイ後に更新する必要があります
    log_warn "ConfigMapのDB_HOSTとREDIS_HOSTは、Terraformデプロイ後に実際のIPアドレスに更新してください"
    
    log_success "設定ファイル更新完了"
}

# メイン処理
main() {
    log_info "Glen ID Platform - Secret設定スクリプト"
    echo
    
    # 前提条件チェック
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl が見つかりません"
        exit 1
    fi
    
    # シークレット情報の取得
    get_secrets
    
    # Kubernetesシークレット作成
    create_k8s_secrets
    
    # terraform.tfvarsファイル作成
    create_terraform_vars
    
    # 設定ファイルの更新
    update_config_files
    
    # GitHub Secretsの設定ガイド
    show_github_secrets_guide
    
    log_success "シークレット設定完了！"
    echo
    log_info "次のステップ:"
    echo "1. GitHub Secretsを設定"
    echo "2. ./scripts/deploy.sh terraform を実行"
    echo "3. ConfigMapのIPアドレスを更新"
    echo "4. ./scripts/deploy.sh kubernetes を実行"
    echo
    log_info "代替方法："
    echo "自動生成スクリプトを使用: ./scripts/generate-secrets.sh"
}

# スクリプト実行
main "$@"