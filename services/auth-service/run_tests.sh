#!/bin/bash

export GOROOT=/home/dqx0/local/go
export GOPATH=/home/dqx0/glen
export PATH=/home/dqx0/local/go/bin:$PATH

cd /home/dqx0/glen/services/auth-service

echo "Running auth service tests..."
go test ./internal/service -v
echo "Running repository tests..."  
go test ./internal/repository -v
echo "Running model tests..."
go test ./internal/models -v