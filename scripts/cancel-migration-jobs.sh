#!/bin/bash

# Cancel stuck migration jobs script

set -e

NAMESPACE="glen-system"

echo "=== Cancel Stuck Migration Jobs ==="
echo "Time: $(date)"
echo "===================================="

# Find all migration jobs
MIGRATION_JOBS=$(kubectl get jobs -n $NAMESPACE -o name 2>/dev/null | grep -E "glen-db-migration|migration" || echo "")

if [ -z "$MIGRATION_JOBS" ]; then
    echo "No migration jobs found"
    exit 0
fi

echo "Found migration jobs:"
echo "$MIGRATION_JOBS"

echo ""
echo "Current status:"
for job in $MIGRATION_JOBS; do
    JOB_NAME=$(echo $job | cut -d'/' -f2)
    COMPLETE=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "Unknown")
    FAILED=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || echo "Unknown")
    echo "  $JOB_NAME: Complete=$COMPLETE, Failed=$FAILED"
done

echo ""
read -p "Do you want to cancel all migration jobs? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelling migration jobs..."
    for job in $MIGRATION_JOBS; do
        JOB_NAME=$(echo $job | cut -d'/' -f2)
        echo "  Deleting $JOB_NAME..."
        kubectl delete job $JOB_NAME -n $NAMESPACE --force --grace-period=0 2>/dev/null || echo "    Failed to delete $JOB_NAME"
    done
    
    echo ""
    echo "Waiting for cleanup..."
    sleep 5
    
    echo "Remaining migration jobs:"
    kubectl get jobs -n $NAMESPACE 2>/dev/null | grep -E "glen-db-migration|migration" || echo "All migration jobs cancelled"
else
    echo "Operation cancelled"
fi

echo "===================================="
