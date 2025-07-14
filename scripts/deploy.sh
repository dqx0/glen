#!/bin/bash

# Glen ID Platform Deployment Script
# 使用方法: ./deploy.sh [terraform|kubernetes|all]

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

# 設定
PROJECT_ID=${PROJECT_ID}
REGION=${GCP_REGION}
ZONE=${GCP_ZONE}
CLUSTER_NAME=${CLUSTER_NAME}
DOCKER_HUB_USERNAME=${DOCKER_HUB_USERNAME}

# 前提条件チェック
check_prerequisites() {
    log_info "前提条件をチェック中..."
    
    # 必要なツールの確認
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI が見つかりません"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl が見つかりません"
        exit 1
    fi
    
    if ! command -v terraform &> /dev/null; then
        log_error "terraform が見つかりません"
        exit 1
    fi
    
    # GCP認証確認
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        log_error "GCP認証が必要です。'gcloud auth login' を実行してください"
        exit 1
    fi
    
    # プロジェクト設定確認
    CURRENT_PROJECT=$(gcloud config get-value project)
    if [ "$CURRENT_PROJECT" != "$PROJECT_ID" ]; then
        log_warn "プロジェクトを $PROJECT_ID に設定中..."
        gcloud config set project $PROJECT_ID
    fi
    
    log_success "前提条件チェック完了"
}

# Terraform デプロイ
deploy_terraform() {
    log_info "Terraformでインフラストラクチャをデプロイ中..."
    
    cd infrastructure/terraform
    
    # terraform.tfvarsファイルの存在確認
    if [ ! -f "terraform.tfvars" ]; then
        log_error "terraform.tfvars ファイルが見つかりません"
        log_info "terraform.tfvars.example を参考にファイルを作成してください"
        exit 1
    fi
    
    # Terraform初期化
    terraform init
    
    # プランの実行
    terraform plan -out=tfplan
    
    # 適用の確認
    read -p "Terraformプランを適用しますか？ (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        terraform apply tfplan
        log_success "Terraform デプロイ完了"
    else
        log_warn "Terraform デプロイをキャンセルしました"
        exit 1
    fi
    
    cd ../..
}

# Kubernetes デプロイ
deploy_kubernetes() {
    log_info "Kubernetesマニフェストをデプロイ中..."
    
    # GKEクラスタの認証情報取得
    gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE --project $PROJECT_ID
    
    # シークレットの設定確認
    if ! kubectl get secret glen-secrets -n glen-system &> /dev/null; then
        log_warn "glen-secrets シークレットが設定されていません"
        log_info "infrastructure/k8s/secret.yaml を編集して、シークレットを設定してください"
        read -p "シークレットを設定しましたか？ (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "シークレットの設定が必要です"
            exit 1
        fi
    fi
    
    # Kubernetesマニフェストの適用
    kubectl apply -f infrastructure/k8s/
    
    # デプロイメントの状態確認
    log_info "デプロイメントの状態を確認中..."
    kubectl rollout status deployment/glen-auth-service -n glen-system
    kubectl rollout status deployment/glen-user-service -n glen-system
    kubectl rollout status deployment/glen-social-service -n glen-system
    kubectl rollout status deployment/glen-api-gateway -n glen-system
    kubectl rollout status deployment/glen-frontend -n glen-system
    
    log_success "Kubernetes デプロイ完了"
}

# デプロイ状態の確認
check_deployment() {
    log_info "デプロイメント状態を確認中..."
    
    # Pod状態の確認
    echo "=== Pod状態 ==="
    kubectl get pods -n glen-system
    
    # Service状態の確認
    echo "=== Service状態 ==="
    kubectl get services -n glen-system
    
    # Ingress状態の確認
    echo "=== Ingress状態 ==="
    kubectl get ingress -n glen-system
    
    # 外部IPの取得
    FRONTEND_IP=$(kubectl get service glen-frontend-service -n glen-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    API_IP=$(kubectl get service glen-api-gateway-service -n glen-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    if [ ! -z "$FRONTEND_IP" ]; then
        log_success "フロントエンド: http://$FRONTEND_IP"
        log_success "フロントエンドヘルスチェック: http://$FRONTEND_IP/health"
    fi
    
    if [ ! -z "$API_IP" ]; then
        log_success "API: http://$API_IP"
        log_success "APIヘルスチェック: http://$API_IP/health"
    fi
    
    log_info "SSL証明書の設定とDNSレコードの更新を忘れずに行ってください"
}

# ヘルスチェック
health_check() {
    log_info "ヘルスチェック実行中..."
    
    # 各サービスのヘルスチェック
    SERVICES=("glen-auth-service" "glen-user-service" "glen-social-service" "glen-api-gateway")
    
    for service in "${SERVICES[@]}"; do
        if kubectl get pods -n glen-system -l app=$service | grep -q Running; then
            log_success "$service: 正常"
        else
            log_error "$service: 異常"
        fi
    done
}

# メイン処理
main() {
    check_prerequisites
    
    case ${1:-all} in
        terraform)
            deploy_terraform
            ;;
        kubernetes)
            deploy_kubernetes
            check_deployment
            health_check
            ;;
        all)
            deploy_terraform
            deploy_kubernetes
            check_deployment
            health_check
            ;;
        *)
            echo "使用方法: $0 [terraform|kubernetes|all]"
            exit 1
            ;;
    esac
    
    log_success "デプロイメント完了！"
}

# スクリプト実行
main "$@"