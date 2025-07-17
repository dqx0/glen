#!/bin/bash

# Glen Database Security Validation Script
# This script validates the security configuration of the Cloud SQL instance

set -e

PROJECT_ID="glen-465915"
INSTANCE_NAME="glen-postgres"

echo "🔍 Validating Glen Database Security Configuration..."
echo "=================================================="

# Check if instance exists
echo "✅ Checking if instance exists..."
if ! gcloud sql instances describe $INSTANCE_NAME --project=$PROJECT_ID >/dev/null 2>&1; then
    echo "❌ Error: Instance $INSTANCE_NAME not found in project $PROJECT_ID"
    exit 1
fi

# Get instance details
echo "📋 Getting instance configuration..."
INSTANCE_INFO=$(gcloud sql instances describe $INSTANCE_NAME --project=$PROJECT_ID --format=json)

# Check private network configuration
echo "🔐 Checking private network configuration..."
PRIVATE_NETWORK=$(echo "$INSTANCE_INFO" | jq -r '.settings.ipConfiguration.privateNetwork // "null"')
if [ "$PRIVATE_NETWORK" != "null" ]; then
    echo "✅ Private network enabled: $PRIVATE_NETWORK"
else
    echo "⚠️  Warning: Private network not configured"
fi

# Check if public IP is disabled or restricted
echo "🌐 Checking public IP configuration..."
IPV4_ENABLED=$(echo "$INSTANCE_INFO" | jq -r '.settings.ipConfiguration.ipv4Enabled')
if [ "$IPV4_ENABLED" = "true" ]; then
    echo "⚠️  Public IP is enabled"
    
    # Check authorized networks
    echo "🔍 Checking authorized networks..."
    AUTHORIZED_NETWORKS=$(echo "$INSTANCE_INFO" | jq -r '.settings.ipConfiguration.authorizedNetworks[]?.value // empty' | sort)
    
    if [ -z "$AUTHORIZED_NETWORKS" ]; then
        echo "✅ No authorized networks configured (VPC-only access)"
    else
        echo "📋 Authorized networks:"
        echo "$AUTHORIZED_NETWORKS" | while read -r network; do
            if [ "$network" = "0.0.0.0/0" ]; then
                echo "❌ SECURITY RISK: $network (allows access from anywhere)"
            else
                echo "✅ $network (restricted access)"
            fi
        done
    fi
else
    echo "✅ Public IP is disabled"
fi

# Check deletion protection
echo "🛡️  Checking deletion protection..."
DELETION_PROTECTION=$(echo "$INSTANCE_INFO" | jq -r '.settings.deletionProtectionEnabled // false')
if [ "$DELETION_PROTECTION" = "true" ]; then
    echo "✅ Deletion protection enabled"
else
    echo "⚠️  Warning: Deletion protection not enabled"
fi

# Check backup configuration
echo "💾 Checking backup configuration..."
BACKUP_ENABLED=$(echo "$INSTANCE_INFO" | jq -r '.settings.backupConfiguration.enabled // false')
if [ "$BACKUP_ENABLED" = "true" ]; then
    echo "✅ Backup enabled"
    
    PITR_ENABLED=$(echo "$INSTANCE_INFO" | jq -r '.settings.backupConfiguration.pointInTimeRecoveryEnabled // false')
    if [ "$PITR_ENABLED" = "true" ]; then
        echo "✅ Point-in-time recovery enabled"
    else
        echo "⚠️  Point-in-time recovery not enabled"
    fi
else
    echo "❌ Backup not enabled"
fi

# Check database flags for security
echo "🔧 Checking security-related database flags..."
DB_FLAGS=$(echo "$INSTANCE_INFO" | jq -r '.settings.databaseFlags[]? | "\(.name)=\(.value)"')

SECURITY_FLAGS=(
    "log_connections"
    "log_disconnections"
    "log_statement"
    "log_checkpoints"
    "log_lock_waits"
    "log_min_duration_statement"
)

for flag in "${SECURITY_FLAGS[@]}"; do
    if echo "$DB_FLAGS" | grep -q "^$flag="; then
        VALUE=$(echo "$DB_FLAGS" | grep "^$flag=" | cut -d= -f2)
        echo "✅ $flag = $VALUE"
    else
        echo "⚠️  $flag not configured"
    fi
done

# Summary
echo ""
echo "📊 Security Assessment Summary"
echo "=============================="

SECURITY_SCORE=0
TOTAL_CHECKS=6

# Check 1: No 0.0.0.0/0 in authorized networks
if ! echo "$AUTHORIZED_NETWORKS" | grep -q "0.0.0.0/0"; then
    echo "✅ No unrestricted network access"
    ((SECURITY_SCORE++))
else
    echo "❌ Unrestricted network access detected"
fi

# Check 2: Private network configured
if [ "$PRIVATE_NETWORK" != "null" ]; then
    echo "✅ Private network configured"
    ((SECURITY_SCORE++))
else
    echo "❌ Private network not configured"
fi

# Check 3: Deletion protection
if [ "$DELETION_PROTECTION" = "true" ]; then
    echo "✅ Deletion protection enabled"
    ((SECURITY_SCORE++))
else
    echo "❌ Deletion protection not enabled"
fi

# Check 4: Backup enabled
if [ "$BACKUP_ENABLED" = "true" ]; then
    echo "✅ Backup enabled"
    ((SECURITY_SCORE++))
else
    echo "❌ Backup not enabled"
fi

# Check 5: Point-in-time recovery
if [ "$PITR_ENABLED" = "true" ]; then
    echo "✅ Point-in-time recovery enabled"
    ((SECURITY_SCORE++))
else
    echo "❌ Point-in-time recovery not enabled"
fi

# Check 6: Security logging
if echo "$DB_FLAGS" | grep -q "log_connections=on"; then
    echo "✅ Security logging enabled"
    ((SECURITY_SCORE++))
else
    echo "❌ Security logging not properly configured"
fi

echo ""
echo "🎯 Security Score: $SECURITY_SCORE/$TOTAL_CHECKS"

if [ $SECURITY_SCORE -eq $TOTAL_CHECKS ]; then
    echo "🎉 Excellent! All security checks passed."
elif [ $SECURITY_SCORE -ge 4 ]; then
    echo "👍 Good security configuration with some improvements needed."
else
    echo "⚠️  Security configuration needs significant improvement."
fi

echo ""
echo "🔗 For more information, see: infrastructure/terraform/README_SECURITY.md"