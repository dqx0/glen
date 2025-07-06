package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dqx0/glen/migrator/internal/config"
	"github.com/dqx0/glen/migrator/internal/database"
	"github.com/dqx0/glen/migrator/internal/migrations"
	"github.com/dqx0/glen/migrator/internal/seeder"
)

const (
	version = "1.0.0"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "Show version")
		showHelp    = flag.Bool("help", false, "Show help")
		command     = flag.String("cmd", "", "Command to run: up, down, status, create, seed, seed-all, clear")
		name        = flag.String("name", "", "Name for create command or specific seed")
		migrationsDir = flag.String("migrations-dir", "migrations", "Directory containing migration files")
		seedsDir      = flag.String("seeds-dir", "seeds", "Directory containing seed files")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Glen Migrator v%s\n", version)
		return
	}

	if *showHelp || *command == "" {
		showUsage()
		return
	}

	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database connection
	db, err := database.NewDB(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Get absolute paths
	migrationsPath := getAbsolutePath(*migrationsDir)
	seedsPath := getAbsolutePath(*seedsDir)

	// Initialize migrator and seeder
	migrator := migrations.NewMigrator(db, migrationsPath)
	seedRunner := seeder.NewSeeder(db, seedsPath)

	// Execute command
	switch *command {
	case "up":
		if err := migrator.Up(); err != nil {
			log.Fatalf("Migration up failed: %v", err)
		}

	case "down":
		if err := migrator.Down(); err != nil {
			log.Fatalf("Migration down failed: %v", err)
		}

	case "status":
		if err := migrator.Status(); err != nil {
			log.Fatalf("Migration status failed: %v", err)
		}

	case "create":
		if *name == "" {
			log.Fatal("Migration name is required for create command")
		}
		if err := migrator.CreateMigration(*name); err != nil {
			log.Fatalf("Create migration failed: %v", err)
		}

	case "seed":
		if *name == "" {
			log.Fatal("Seed name is required for seed command")
		}
		if err := seedRunner.SeedSpecific(*name); err != nil {
			log.Fatalf("Seed failed: %v", err)
		}

	case "seed-all":
		if err := seedRunner.SeedAll(); err != nil {
			log.Fatalf("Seed all failed: %v", err)
		}

	case "clear":
		if err := seedRunner.ClearAll(); err != nil {
			log.Fatalf("Clear all failed: %v", err)
		}

	case "create-seed":
		if *name == "" {
			log.Fatal("Seed name is required for create-seed command")
		}
		if err := seedRunner.CreateSeed(*name); err != nil {
			log.Fatalf("Create seed failed: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showUsage()
		os.Exit(1)
	}
}

func showUsage() {
	fmt.Printf(`Glen Migrator v%s - Database migration and seeding tool

Usage:
  migrator -cmd=<command> [options]

Commands:
  up              Run all pending migrations
  down            Rollback the last migration
  status          Show migration status
  create          Create a new migration file (-name required)
  seed            Run a specific seed file (-name required)
  seed-all        Run all seed files
  clear           Clear all data from tables
  create-seed     Create a new seed file (-name required)

Options:
  -name string           Name for migration/seed creation or specific seed to run
  -migrations-dir string Directory containing migration files (default "migrations")
  -seeds-dir string      Directory containing seed files (default "seeds")
  -version              Show version
  -help                 Show this help

Environment Variables:
  DATABASE_URL    Complete database URL
  DB_HOST         Database host (default "localhost")
  DB_PORT         Database port (default "5432")
  DB_USER         Database user (default "glen_dev")
  DB_PASSWORD     Database password (default "glen_dev_pass")
  DB_NAME         Database name (default "glen_dev")
  DB_SSLMODE      SSL mode (default "disable")
  ENV             Environment (development|test|production)

Examples:
  migrator -cmd=up
  migrator -cmd=status
  migrator -cmd=create -name=add_users_table
  migrator -cmd=seed-all
  migrator -cmd=seed -name=test_users
  migrator -cmd=clear

`, version)
}

func getAbsolutePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	// Use current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	return filepath.Join(cwd, path)
}