#!/bin/bash

# Quick migration status check script
# Use this to check current migration job status

set -e

NAMESPACE="glen-system"

echo "=== Quick Migration Status Check ==="
echo "Time: $(date)"
echo "===================================="

# Find running migration jobs
echo "1. Current migration jobs:"
kubectl get jobs -n $NAMESPACE 2>/dev/null | grep -E "glen-db-migration|migration" || echo "No migration jobs found"

# Check pods for migration jobs
echo ""
echo "2. Migration job pods:"
kubectl get pods -n $NAMESPACE 2>/dev/null | grep -E "glen-db-migration|migration" || echo "No migration pods found"

# Get the latest migration job
LATEST_JOB=$(kubectl get jobs -n $NAMESPACE --sort-by=.metadata.creationTimestamp -o name 2>/dev/null | grep -E "glen-db-migration|migration" | tail -1)

if [ -n "$LATEST_JOB" ]; then
    JOB_NAME=$(echo $LATEST_JOB | cut -d'/' -f2)
    echo ""
    echo "3. Latest migration job details: $JOB_NAME"
    kubectl describe job $JOB_NAME -n $NAMESPACE 2>/dev/null || echo "Could not describe job"
    
    echo ""
    echo "4. Latest migration job logs:"
    kubectl logs -n $NAMESPACE job/$JOB_NAME --tail=30 2>/dev/null || echo "No logs available"
    
    # Check pod status
    POD_NAME=$(kubectl get pods -n $NAMESPACE -l job-name=$JOB_NAME -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$POD_NAME" ]]; then
        echo ""
        echo "5. Pod status: $POD_NAME"
        kubectl describe pod $POD_NAME -n $NAMESPACE 2>/dev/null || echo "Could not describe pod"
    fi
    
    # Check if job is stuck
    echo ""
    echo "6. Job completion status:"
    COMPLETE=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "Unknown")
    FAILED=$(kubectl get job $JOB_NAME -n $NAMESPACE -o jsonpath='{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || echo "Unknown")
    echo "   Complete: $COMPLETE"
    echo "   Failed: $FAILED"
    
    if [[ "$COMPLETE" != "True" && "$FAILED" != "True" ]]; then
        echo "   Status: RUNNING"
        echo ""
        echo "7. To cancel stuck job, run:"
        echo "   kubectl delete job $JOB_NAME -n $NAMESPACE --force --grace-period=0"
    elif [[ "$FAILED" == "True" ]]; then
        echo "   Status: FAILED"
    elif [[ "$COMPLETE" == "True" ]]; then
        echo "   Status: COMPLETED"
    fi
else
    echo "No migration jobs found"
fi

echo ""
echo "===================================="
