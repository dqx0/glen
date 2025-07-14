#!/bin/bash

# Glen ID Platform - モニタリングスクリプト
# 使用方法: ./monitor.sh [status|logs|health|metrics]

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
NAMESPACE="glen-system"
SERVICES=("glen-auth-service" "glen-user-service" "glen-social-service" "glen-api-gateway" "glen-frontend")

# 状態確認
show_status() {
    log_info "Glen ID Platform システム状態"
    echo
    
    # Pod状態
    echo "=== Pod状態 ==="
    kubectl get pods -n $NAMESPACE -o wide
    echo
    
    # Service状態
    echo "=== Service状態 ==="
    kubectl get services -n $NAMESPACE
    echo
    
    # Ingress状態
    echo "=== Ingress状態 ==="
    kubectl get ingress -n $NAMESPACE
    echo
    
    # ConfigMap状態
    echo "=== ConfigMap状態 ==="
    kubectl get configmaps -n $NAMESPACE
    echo
    
    # Secret状態
    echo "=== Secret状態 ==="
    kubectl get secrets -n $NAMESPACE
    echo
}

# ログ表示
show_logs() {
    if [ -n "$2" ]; then
        # 特定のサービスのログ
        SERVICE=$2
        log_info "$SERVICE のログを表示中..."
        kubectl logs -n $NAMESPACE -l app=$SERVICE -f --tail=100
    else
        # 全サービスのログ
        log_info "全サービスのログを表示中..."
        for service in "${SERVICES[@]}"; do
            echo "=== $service ログ ==="
            kubectl logs -n $NAMESPACE -l app=$service --tail=10
            echo
        done
    fi
}

# ヘルスチェック
health_check() {
    log_info "ヘルスチェック実行中..."
    echo
    
    # 各サービスのヘルスチェック
    for service in "${SERVICES[@]}"; do
        READY=$(kubectl get pods -n $NAMESPACE -l app=$service -o jsonpath='{.items[*].status.containerStatuses[*].ready}')
        RUNNING=$(kubectl get pods -n $NAMESPACE -l app=$service -o jsonpath='{.items[*].status.phase}')
        
        if [[ "$READY" == "true" && "$RUNNING" == "Running" ]]; then
            log_success "$service: 正常"
        else
            log_error "$service: 異常 (Ready: $READY, Status: $RUNNING)"
        fi
    done
    echo
    
    # 外部アクセス確認
    log_info "外部アクセス確認中..."
    
    # フロントエンドIP取得
    FRONTEND_IP=$(kubectl get service glen-frontend-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
    if [ ! -z "$FRONTEND_IP" ]; then
        if curl -f -s http://$FRONTEND_IP > /dev/null; then
            log_success "フロントエンド: http://$FRONTEND_IP (正常)"
        else
            log_error "フロントエンド: http://$FRONTEND_IP (異常)"
        fi
    else
        log_warn "フロントエンドの外部IPが取得できません"
    fi
    
    # API IP取得
    API_IP=$(kubectl get service glen-api-gateway-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
    if [ ! -z "$API_IP" ]; then
        if curl -f -s http://$API_IP/health > /dev/null; then
            log_success "API: http://$API_IP/health (正常)"
        else
            log_error "API: http://$API_IP/health (異常)"
        fi
    else
        log_warn "APIの外部IPが取得できません"
    fi
}

# メトリクス表示
show_metrics() {
    log_info "リソース使用量を表示中..."
    echo
    
    # Node使用量
    echo "=== Node使用量 ==="
    kubectl top nodes
    echo
    
    # Pod使用量
    echo "=== Pod使用量 ==="
    kubectl top pods -n $NAMESPACE
    echo
    
    # ストレージ使用量
    echo "=== PersistentVolume使用量 ==="
    kubectl get pv
    echo
    
    # イベント確認
    echo "=== 最近のイベント ==="
    kubectl get events -n $NAMESPACE --sort-by=.metadata.creationTimestamp | tail -10
    echo
}

# トラブルシューティング
troubleshoot() {
    log_info "トラブルシューティング情報を収集中..."
    echo
    
    # 異常なPodの確認
    echo "=== 異常なPod ==="
    kubectl get pods -n $NAMESPACE --field-selector=status.phase!=Running
    echo
    
    # 失敗したPodの詳細
    FAILED_PODS=$(kubectl get pods -n $NAMESPACE --field-selector=status.phase!=Running -o jsonpath='{.items[*].metadata.name}')
    for pod in $FAILED_PODS; do
        if [ ! -z "$pod" ]; then
            echo "=== $pod の詳細 ==="
            kubectl describe pod $pod -n $NAMESPACE
            echo
            echo "=== $pod のログ ==="
            kubectl logs $pod -n $NAMESPACE --tail=20
            echo
        fi
    done
    
    # リソース不足の確認
    echo "=== リソース制限 ==="
    kubectl describe nodes | grep -A 5 "Allocated resources"
    echo
}

# 使用方法表示
show_usage() {
    echo "使用方法: $0 [status|logs|health|metrics|troubleshoot]"
    echo
    echo "コマンド:"
    echo "  status       - システム状態を表示"
    echo "  logs [service] - ログを表示（サービス名指定可能）"
    echo "  health       - ヘルスチェック実行"
    echo "  metrics      - リソース使用量を表示"
    echo "  troubleshoot - トラブルシューティング情報を表示"
    echo
    echo "例:"
    echo "  $0 status"
    echo "  $0 logs glen-auth-service"
    echo "  $0 health"
}

# 前提条件チェック
check_prerequisites() {
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl が見つかりません"
        exit 1
    fi
    
    # namespace存在確認
    if ! kubectl get namespace $NAMESPACE &> /dev/null; then
        log_error "namespace '$NAMESPACE' が存在しません"
        exit 1
    fi
}

# メイン処理
main() {
    check_prerequisites
    
    case ${1:-status} in
        status)
            show_status
            ;;
        logs)
            show_logs "$@"
            ;;
        health)
            health_check
            ;;
        metrics)
            show_metrics
            ;;
        troubleshoot)
            troubleshoot
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "不明なコマンド: $1"
            show_usage
            exit 1
            ;;
    esac
}

# スクリプト実行
main "$@"