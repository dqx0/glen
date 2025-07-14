#!/bin/bash

# Glen ID Platform - シークレット自動生成スクリプト
# 使用方法: ./generate-secrets.sh [--no-interactive]

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

# UUID生成関数
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        openssl rand -hex 16 | sed 's/\(..\)/\1-/g; s/^/\{/; s/-$/\}/'
    fi
}

# 暗号化キー生成関数
generate_encryption_key() {
    openssl rand -base64 32
}

# 全シークレット生成関数
generate_all_secrets() {
    log_info "セキュアなシークレットを生成中..."
    
    # データベース関連
    DB_PASSWORD=$(generate_password 24)
    
    # JWT関連
    JWT_SECRET=$(generate_jwt_secret)
    
    # OAuth関連
    OAUTH_CLIENT_ID=$(generate_client_id)
    OAUTH_CLIENT_SECRET=$(generate_client_secret)
    
    # 暗号化キー
    ENCRYPTION_KEY=$(generate_encryption_key)
    
    # セッション関連
    SESSION_SECRET=$(generate_password 32)
    
    # API キー
    API_KEY=$(generate_password 48)
    
    # 管理者用初期パスワード
    ADMIN_PASSWORD=$(generate_password 16)
    
    log_success "全シークレットの生成が完了しました"
}

# 環境変数ファイル作成
create_env_file() {
    local env_file="$1"
    log_info "環境変数ファイルを作成中: $env_file"
    
    cat > "$env_file" << EOF
# Glen ID Platform - Environment Variables
# Generated at: $(date)

# Database Configuration
DB_PASSWORD=$DB_PASSWORD

# JWT Configuration
JWT_SECRET=$JWT_SECRET

# OAuth Configuration
OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID
OAUTH_CLIENT_SECRET=$OAUTH_CLIENT_SECRET

# Encryption
ENCRYPTION_KEY=$ENCRYPTION_KEY

# Session Management
SESSION_SECRET=$SESSION_SECRET

# API Configuration
API_KEY=$API_KEY

# Admin Configuration
ADMIN_PASSWORD=$ADMIN_PASSWORD

# Google OAuth (要手動設定)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# GitHub OAuth (要手動設定)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Discord OAuth (要手動設定)
DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=
EOF
    
    chmod 600 "$env_file"
    log_success "環境変数ファイルを作成しました: $env_file"
}

# Kubernetes secrets YAML作成
create_k8s_secrets_yaml() {
    local yaml_file="$1"
    log_info "Kubernetes secrets YAMLを作成中: $yaml_file"
    
    cat > "$yaml_file" << EOF
apiVersion: v1
kind: Secret
metadata:
  name: glen-secrets
  namespace: glen-system
type: Opaque
data:
  # Auto-generated secrets (Base64 encoded)
  DB_PASSWORD: $(echo -n "$DB_PASSWORD" | base64 -w 0)
  JWT_SECRET: $(echo -n "$JWT_SECRET" | base64 -w 0)
  OAUTH_CLIENT_ID: $(echo -n "$OAUTH_CLIENT_ID" | base64 -w 0)
  OAUTH_CLIENT_SECRET: $(echo -n "$OAUTH_CLIENT_SECRET" | base64 -w 0)
  ENCRYPTION_KEY: $(echo -n "$ENCRYPTION_KEY" | base64 -w 0)
  SESSION_SECRET: $(echo -n "$SESSION_SECRET" | base64 -w 0)
  API_KEY: $(echo -n "$API_KEY" | base64 -w 0)
  ADMIN_PASSWORD: $(echo -n "$ADMIN_PASSWORD" | base64 -w 0)
  
  # Manual configuration required (empty values)
  GOOGLE_CLIENT_ID: ""
  GOOGLE_CLIENT_SECRET: ""
  GITHUB_CLIENT_ID: ""
  GITHUB_CLIENT_SECRET: ""
  DISCORD_CLIENT_ID: ""
  DISCORD_CLIENT_SECRET: ""
EOF
    
    chmod 600 "$yaml_file"
    log_success "Kubernetes secrets YAMLを作成しました: $yaml_file"
}

# terraform.tfvars作成
create_terraform_vars() {
    local tfvars_file="$1"
    log_info "terraform.tfvarsを作成中: $tfvars_file"
    
    cat > "$tfvars_file" << EOF
# Glen ID Platform - Terraform Variables
# Generated at: $(date)

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
    
    chmod 600 "$tfvars_file"
    log_success "terraform.tfvarsを作成しました: $tfvars_file"
}

# シークレット情報の表示
display_secrets() {
    log_info "生成されたシークレット情報"
    echo
    echo "データベースパスワード: $DB_PASSWORD"
    echo "JWTシークレット: $JWT_SECRET"
    echo "OAuth Client ID: $OAUTH_CLIENT_ID"
    echo "OAuth Client Secret: $OAUTH_CLIENT_SECRET"
    echo "管理者パスワード: $ADMIN_PASSWORD"
    echo
    log_warn "これらの情報は安全に保管してください"
}

# パスワード強度チェック
check_password_strength() {
    local password="$1"
    local name="$2"
    
    if [ ${#password} -lt 16 ]; then
        log_warn "$name: パスワードが16文字未満です"
        return 1
    fi
    
    if ! [[ "$password" =~ [A-Za-z] ]]; then
        log_warn "$name: パスワードに英字が含まれていません"
        return 1
    fi
    
    if ! [[ "$password" =~ [0-9] ]]; then
        log_warn "$name: パスワードに数字が含まれていません"
        return 1
    fi
    
    log_success "$name: パスワード強度チェック合格"
    return 0
}

# 前提条件チェック
check_prerequisites() {
    log_info "前提条件をチェック中..."
    
    if ! command -v openssl &> /dev/null; then
        log_error "opensslが見つかりません"
        exit 1
    fi
    
    if ! command -v base64 &> /dev/null; then
        log_error "base64が見つかりません"
        exit 1
    fi
    
    log_success "前提条件チェック完了"
}

# 使用方法表示
show_usage() {
    echo "使用方法: $0 [OPTIONS]"
    echo
    echo "オプション:"
    echo "  --no-interactive    インタラクティブモードを無効にする"
    echo "  --output-dir DIR    出力ディレクトリを指定 (default: .)"
    echo "  --help              このヘルプを表示"
    echo
    echo "例:"
    echo "  $0                                # インタラクティブモードで実行"
    echo "  $0 --no-interactive               # 自動生成のみ実行"
    echo "  $0 --output-dir ./secrets         # 出力ディレクトリを指定"
}

# メイン処理
main() {
    local interactive=true
    local output_dir="."
    
    # 引数解析
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-interactive)
                interactive=false
                shift
                ;;
            --output-dir)
                output_dir="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "不明なオプション: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # 出力ディレクトリの作成
    mkdir -p "$output_dir"
    
    log_info "Glen ID Platform - シークレット自動生成スクリプト"
    echo
    
    # 前提条件チェック
    check_prerequisites
    
    # インタラクティブモードでの確認
    if [ "$interactive" = true ]; then
        read -p "シークレットを自動生成しますか？ (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            log_info "処理をキャンセルしました"
            exit 0
        fi
    fi
    
    # シークレット生成
    generate_all_secrets
    
    # パスワード強度チェック
    check_password_strength "$DB_PASSWORD" "データベースパスワード"
    check_password_strength "$JWT_SECRET" "JWTシークレット"
    check_password_strength "$ADMIN_PASSWORD" "管理者パスワード"
    
    # ファイル作成
    create_env_file "$output_dir/.env.secrets"
    create_k8s_secrets_yaml "$output_dir/k8s-secrets.yaml"
    create_terraform_vars "$output_dir/terraform.tfvars"
    
    # 結果表示
    if [ "$interactive" = true ]; then
        display_secrets
    fi
    
    log_success "シークレット生成完了！"
    echo
    log_info "次のステップ:"
    echo "1. 生成されたファイルを確認"
    echo "2. 必要に応じてソーシャルOAuth設定を追加"
    echo "3. terraform.tfvarsを infrastructure/terraform/ に配置"
    echo "4. k8s-secrets.yamlを kubectl apply で適用"
}

# スクリプト実行
main "$@"