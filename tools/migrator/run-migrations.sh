#!/bin/sh

# Run migrations
echo "Running database migrations..."
./migrator -cmd=up

# Check if migrations were successful
if [ $? -eq 0 ]; then
    echo "Migrations completed successfully"
    
    # Run seed data in development environment
    if [ "$ENV" = "development" ] || [ "$ENV" = "dev" ] || [ -z "$ENV" ]; then
        echo "Running seed data..."
        ./migrator -cmd=seed-all
        if [ $? -eq 0 ]; then
            echo "Seed data inserted successfully"
        else
            echo "Warning: Failed to insert seed data"
        fi
    fi
else
    echo "Migration failed"
    exit 1
fi