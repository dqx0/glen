#!/bin/bash

# Glen ID Platform - Database Migration Debug Script
# This script helps debug database migration issues

set -e

NAMESPACE="glen-system"

echo "=== Glen Database Migration Debug ==="
echo "Date: $(date)"
echo "=================================="

# Check if namespace exists
echo "1. Checking namespace..."
if kubectl get namespace $NAMESPACE > /dev/null 2>&1; then
    echo "✓ Namespace '$NAMESPACE' exists"
else
    echo "✗ Namespace '$NAMESPACE' does not exist"
    exit 1
fi

# Check ConfigMap
echo "2. Checking migration ConfigMap..."
if kubectl get configmap glen-db-migrations -n $NAMESPACE > /dev/null 2>&1; then
    echo "✓ Migration ConfigMap exists"
    echo "   ConfigMap data keys:"
    kubectl get configmap glen-db-migrations -n $NAMESPACE -o jsonpath='{.data}' | jq -r 'keys[]' 2>/dev/null || echo "   (Could not parse keys)"
else
    echo "✗ Migration ConfigMap does not exist"
fi

# Check recent migration jobs
echo "3. Checking migration jobs..."
JOBS=$(kubectl get jobs -n $NAMESPACE --selector=app!=glen-system -o name 2>/dev/null | grep -E "glen-db-migration|migration" || echo "")
if [ -n "$JOBS" ]; then
    echo "✓ Found migration jobs:"
    kubectl get jobs -n $NAMESPACE --selector=app!=glen-system --sort-by=.metadata.creationTimestamp 2>/dev/null || true
    
    # Get the latest migration job
    LATEST_JOB=$(kubectl get jobs -n $NAMESPACE --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | grep -E "glen-db-migration|migration" | tail -1)
    if [ -n "$LATEST_JOB" ]; then
        JOB_NAME=$(echo $LATEST_JOB | cut -d'/' -f2)
        echo "   Latest job: $JOB_NAME"
        echo "   Job status:"
        kubectl get job $JOB_NAME -n $NAMESPACE -o wide 2>/dev/null || true
        
        echo "   Job logs (last 50 lines):"
        kubectl logs -n $NAMESPACE job/$JOB_NAME --tail=50 2>/dev/null || echo "   (No logs available)"
    fi
else
    echo "✗ No migration jobs found"
fi

# Check if we can connect to database from within cluster
echo "4. Testing database connection..."
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: glen-db-test-$(date +%s)
  namespace: $NAMESPACE
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: db-test
        image: postgres:15-alpine
        command:
        - /bin/sh
        - -c
        - |
          echo "Testing database connection..."
          echo "DB_HOST: \$DB_HOST"
          echo "Attempting to connect..."
          
          # Test basic connection
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT version();" || echo "Connection failed"
          
          # Check if users table exists
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "\\dt" | grep users || echo "users table not found"
          
          # Check migration history
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT * FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;" 2>/dev/null || echo "No schema_migrations table"
        env:
        - name: DB_HOST
          valueFrom:
            configMapKeyRef:
              name: glen-config
              key: DB_HOST
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: glen-secrets
              key: DB_PASSWORD
EOF

echo "✓ Database test job created. Wait a moment for completion..."
sleep 15

# Get the test job name
TEST_JOB=$(kubectl get jobs -n $NAMESPACE --sort-by=.metadata.creationTimestamp -o name | tail -1 | cut -d'/' -f2)
echo "5. Database test results:"
kubectl logs -n $NAMESPACE job/$TEST_JOB 2>/dev/null || echo "   (No logs available yet)"

# Check deployments status
echo "6. Checking service deployments..."
SERVICES=("glen-auth-service" "glen-user-service" "glen-social-service" "glen-api-gateway" "glen-frontend")
for service in "${SERVICES[@]}"; do
    if kubectl get deployment $service -n $NAMESPACE > /dev/null 2>&1; then
        READY=$(kubectl get deployment $service -n $NAMESPACE -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        DESIRED=$(kubectl get deployment $service -n $NAMESPACE -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
        echo "   $service: $READY/$DESIRED ready"
    else
        echo "   $service: not found"
    fi
done

echo "=================================="
echo "Debug completed. Check the output above for issues."
echo "=================================="

# Clean up test job
kubectl delete job $TEST_JOB -n $NAMESPACE 2>/dev/null || true
