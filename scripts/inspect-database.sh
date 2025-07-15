#!/bin/bash

# Database schema inspection script

set -e

NAMESPACE="glen-system"
JOB_NAME="glen-db-inspect-$(date +%s)"

echo "=== Database Schema Inspection ==="
echo "Time: $(date)"
echo "=================================="

# Create inspection job
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: $JOB_NAME
  namespace: $NAMESPACE
spec:
  activeDeadlineSeconds: 300
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: db-inspector
        image: postgres:15-alpine
        command:
        - /bin/sh
        - -c
        - |
          echo "=== Database Schema Inspection ==="
          echo "Time: \$(date)"
          echo "DB_HOST: \$DB_HOST"
          echo "=================================="
          
          # Check all tables
          echo "1. All tables in database:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "\\dt"
          
          # Check schema_migrations table
          echo ""
          echo "2. Migration history:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT version, dirty, applied_at FROM schema_migrations ORDER BY applied_at DESC;" || echo "No schema_migrations table"
          
          # Check if users table exists specifically
          echo ""
          echo "3. Checking users table:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'users';"
          
          # Show all table names
          echo ""
          echo "4. All table names:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;"
          
          # Check current migration version
          echo ""
          echo "5. Current migration version (using migrate tool):"
          migrate -path /tmp -database "postgres://glen_user:\$DB_PASSWORD@\$DB_HOST:5432/glen_prod?sslmode=require" version || echo "Cannot determine version"
          
          echo ""
          echo "Inspection completed at: \$(date)"
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

echo "Inspection job created: $JOB_NAME"
echo "Waiting for completion..."

# Wait for completion
for i in {1..30}; do
  STATUS=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "")
  FAILED=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || echo "")
  
  if [[ "$STATUS" == "True" ]]; then
    echo "Inspection completed!"
    break
  elif [[ "$FAILED" == "True" ]]; then
    echo "Inspection failed!"
    break
  fi
  
  echo "Waiting... ($i/30)"
  sleep 5
done

# Show results
echo ""
echo "=== Inspection Results ==="
kubectl logs -n $NAMESPACE job/$JOB_NAME

# Clean up
echo ""
echo "Cleaning up inspection job..."
kubectl delete job $JOB_NAME -n $NAMESPACE

echo "============================"
