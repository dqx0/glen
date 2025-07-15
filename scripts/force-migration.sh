#!/bin/bash

# Manual database migration script for Glen ID Platform
# This script forces a fresh migration run

set -e

NAMESPACE="glen-system"
JOB_NAME="glen-migration-manual-$(date +%s)"

echo "=== Manual Database Migration ==="
echo "Job Name: $JOB_NAME"
echo "================================="

# Ensure ConfigMap is updated
echo "1. Creating/updating migration ConfigMap..."
kubectl create configmap glen-db-migrations \
  --from-file=tools/migrator/migrations/ \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✓ ConfigMap updated"

# Create migration job with enhanced debugging
echo "2. Creating migration job..."
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: $JOB_NAME
  namespace: $NAMESPACE
spec:
  backoffLimit: 3
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: migrator
        image: migrate/migrate:v4.16.2
        command:
        - /bin/sh
        - -c
        - |
          echo "=== Glen Database Migration ==="
          echo "Starting at: \$(date)"
          echo "DB_HOST: \$DB_HOST"
          echo "==============================="
          
          # Install postgresql client for debugging
          apk add --no-cache postgresql-client
          
          # Test basic database connection
          echo "Testing database connection..."
          until PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT 1;" > /dev/null 2>&1; do
            echo "Database connection failed, retrying in 5 seconds..."
            sleep 5
          done
          echo "✓ Database connection successful"
          
          # Check current database state
          echo "Current database tables:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "\\dt" || echo "No tables found"
          
          # Check migration tool connection
          echo "Testing migration tool connection..."
          DB_URL="postgres://glen_user:\$DB_PASSWORD@\$DB_HOST:5432/glen_prod?sslmode=require"
          
          # List available migration files
          echo "Available migration files:"
          ls -la /migrations/
          
          # Check current migration version
          echo "Checking current migration version..."
          migrate -path /migrations -database "\$DB_URL" version || echo "No migrations applied yet"
          
          # Force clean if dirty
          if migrate -path /migrations -database "\$DB_URL" version 2>&1 | grep -q "dirty"; then
            echo "Database is dirty, forcing clean..."
            migrate -path /migrations -database "\$DB_URL" force 20250706000001
          fi
          
          # Run migrations
          echo "Running migrations..."
          migrate -path /migrations -database "\$DB_URL" up -verbose
          
          # Verify tables were created
          echo "Verifying tables after migration:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "\\dt"
          
          # Check users table specifically
          echo "Checking users table:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "\\d users" || echo "users table not found"
          
          # Check migration history
          echo "Migration history:"
          PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U glen_user -d glen_prod -c "SELECT version, dirty, applied_at FROM schema_migrations ORDER BY applied_at DESC;" || echo "No migration history"
          
          echo "Migration completed at: \$(date)"
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
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: glen-db-migrations
EOF

echo "✓ Migration job created"

# Wait for completion
echo "3. Waiting for migration to complete..."
for i in {1..60}; do
  STATUS=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "")
  FAILED=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || echo "")
  
  if [[ "$STATUS" == "True" ]]; then
    echo "✓ Migration completed successfully!"
    break
  elif [[ "$FAILED" == "True" ]]; then
    echo "✗ Migration failed!"
    break
  fi
  
  echo "   Waiting... ($i/60)"
  sleep 10
done

# Show results
echo "4. Migration results:"
kubectl logs -n $NAMESPACE job/$JOB_NAME

echo "5. Final job status:"
kubectl get job $JOB_NAME -n $NAMESPACE -o wide

echo "================================="
echo "Manual migration completed."
echo "To clean up: kubectl delete job $JOB_NAME -n $NAMESPACE"
echo "================================="
