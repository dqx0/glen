#!/bin/bash

# .env.secretsを環境変数として読み込むスクリプト
# 使用方法: source ./scripts/load-env-secrets.sh

if [ -f ".env.secrets" ]; then
    echo "Loading environment variables from .env.secrets..."
    
    # .env.secretsから環境変数を読み込み
    export $(grep -v '^#' .env.secrets | xargs)
    
    echo "✅ Environment variables loaded:"
    echo "- DB_PASSWORD: [HIDDEN]"
    echo "- JWT_SECRET: [HIDDEN]"
    echo "- OAUTH_CLIENT_ID: $OAUTH_CLIENT_ID"
    echo "- ADMIN_PASSWORD: [HIDDEN]"
    
    echo ""
    echo "使用例:"
    echo "  make dev-services    # ローカル開発"
    echo "  make test           # テスト実行"
    
else
    echo "❌ .env.secrets file not found"
    echo "Run: ./scripts/generate-secrets.sh"
fi