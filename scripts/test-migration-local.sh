#!/bin/bash

# Local migration test script
# This tests the migration files locally using Docker

set -e

echo "=== Local Migration Test ==="

# Start local PostgreSQL for testing
echo "Starting local PostgreSQL..."
docker run --name glen-test-db -d \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_USER=glen_user \
  -e POSTGRES_DB=glen_test \
  -p 5433:5432 \
  postgres:15-alpine

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 10

# Test migration using migrate tool
echo "Testing migration..."
docker run --rm \
  --network host \
  -v $(pwd)/tools/migrator/migrations:/migrations \
  migrate/migrate:v4.16.2 \
  -path /migrations \
  -database "postgres://glen_user:testpass@localhost:5433/glen_test?sslmode=disable" \
  up

# Check if tables were created
echo "Checking created tables..."
docker run --rm \
  --network host \
  -e PGPASSWORD=testpass \
  postgres:15-alpine \
  psql -h localhost -p 5433 -U glen_user -d glen_test \
  -c "\\dt"

# Check users table specifically
echo "Checking users table structure..."
docker run --rm \
  --network host \
  -e PGPASSWORD=testpass \
  postgres:15-alpine \
  psql -h localhost -p 5433 -U glen_user -d glen_test \
  -c "\\d users"

# Clean up
echo "Cleaning up..."
docker stop glen-test-db
docker rm glen-test-db

echo "Local migration test completed successfully!"
