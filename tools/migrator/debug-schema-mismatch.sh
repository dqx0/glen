#!/bin/bash

echo "=== Schema Mismatch Debug ==="
echo "現在の日時: $(date)"
echo ""

# PostgreSQL環境変数の確認
echo "1. PostgreSQL環境変数:"
echo "   POSTGRES_DB: ${POSTGRES_DB:-default.env値}"
echo "   POSTGRES_USER: ${POSTGRES_USER:-default.env値}"
echo "   DB_HOST: ${DB_HOST:-default.env値}"
echo ""

# マイグレーションファイルの確認
echo "2. マイグレーションファイル一覧:"
ls -la /home/dqx0/glen/tools/migrator/migrations/
echo ""

# ファイル内容の比較
echo "3. マイグレーションファイルの問題分析:"
echo ""

echo "--- webauthn_credentials テーブルの定義 ---"
echo "マイグレーションファイル (PostgreSQL形式):"
grep -A 10 "CREATE TABLE webauthn_credentials" /home/dqx0/glen/tools/migrator/migrations/20250706000001_initial_schema.up.sql

echo ""
echo "Goコード期待値 (SQLite互換形式):"
echo "CREATE TABLE webauthn_credentials ("
echo "    id TEXT NOT NULL PRIMARY KEY,"
echo "    user_id TEXT NOT NULL,"
echo "    credential_id BLOB NOT NULL UNIQUE,"  # BYTEAではなくBLOB
echo "    public_key BLOB NOT NULL,"            # BYTEAではなくBLOB  
echo "    attestation_type TEXT DEFAULT 'none',"
echo "    transport TEXT DEFAULT '',"
echo "    user_present BOOLEAN NOT NULL DEFAULT 0,"     # 追加フィールド
echo "    user_verified BOOLEAN NOT NULL DEFAULT 0,"    # 追加フィールド
echo "    backup_eligible BOOLEAN NOT NULL DEFAULT 0,"  # 追加フィールド
echo "    backup_state BOOLEAN NOT NULL DEFAULT 0,"     # 追加フィールド
echo "    sign_count INTEGER NOT NULL DEFAULT 0,"       # BIGINTではなくINTEGER
echo "    clone_warning BOOLEAN NOT NULL DEFAULT 0,"    # BOOLEAN DEFAULT FALSEではなく
echo "    name TEXT NOT NULL DEFAULT '',"               # 位置が違う
echo "    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
echo "    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
echo "    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
echo ");"
echo ""

echo "4. 主な違い:"
echo "   - BYTEA vs BLOB (PostgreSQL vs SQLite)"
echo "   - BOOLEAN DEFAULT FALSE vs BOOLEAN NOT NULL DEFAULT 0"
echo "   - JSONB vs TEXT (PostgreSQL vs SQLite)"
echo "   - 不足カラム: user_present, user_verified, backup_eligible, backup_state"
echo "   - BIGINT vs INTEGER"
echo ""

echo "5. 解決策:"
echo "   PostgreSQL互換のマイグレーションを作成する必要があります"
echo "   既存のマイグレーションを修正し、不足カラムを追加します"
echo ""

echo "=== End Debug ==="
