package seeder

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dqx0/glen/migrator/internal/database"
)

// Seed represents a database seed file
type Seed struct {
	Name     string
	Filename string
	SQL      string
}

// Seeder handles database seeding
type Seeder struct {
	db       *database.DB
	seedsDir string
}

// NewSeeder creates a new seeder instance
func NewSeeder(db *database.DB, seedsDir string) *Seeder {
	return &Seeder{
		db:       db,
		seedsDir: seedsDir,
	}
}

// LoadSeeds loads all seed files from the seeds directory
func (s *Seeder) LoadSeeds() ([]*Seed, error) {
	var seeds []*Seed

	err := filepath.WalkDir(s.seedsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		seed, err := s.parseSeedFile(path)
		if err != nil {
			return fmt.Errorf("failed to parse seed file %s: %w", path, err)
		}

		seeds = append(seeds, seed)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load seeds: %w", err)
	}

	// Sort seeds by filename
	sort.Slice(seeds, func(i, j int) bool {
		return seeds[i].Filename < seeds[j].Filename
	})

	return seeds, nil
}

// parseSeedFile parses a seed file and extracts SQL
func (s *Seeder) parseSeedFile(filePath string) (*Seed, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	filename := filepath.Base(filePath)
	name := strings.TrimSuffix(filename, ".sql")

	return &Seed{
		Name:     name,
		Filename: filename,
		SQL:      string(content),
	}, nil
}

// SeedAll runs all seed files
func (s *Seeder) SeedAll() error {
	seeds, err := s.LoadSeeds()
	if err != nil {
		return err
	}

	if len(seeds) == 0 {
		fmt.Println("No seed files found")
		return nil
	}

	fmt.Printf("Running %d seed files...\n", len(seeds))

	for _, seed := range seeds {
		fmt.Printf("Seeding: %s\n", seed.Name)

		if err := s.runSeed(seed); err != nil {
			return fmt.Errorf("failed to run seed %s: %w", seed.Name, err)
		}

		fmt.Printf("✅ Seeded: %s\n", seed.Name)
	}

	fmt.Println("All seeds completed successfully!")
	return nil
}

// SeedSpecific runs a specific seed file
func (s *Seeder) SeedSpecific(seedName string) error {
	seeds, err := s.LoadSeeds()
	if err != nil {
		return err
	}

	var targetSeed *Seed
	for _, seed := range seeds {
		if seed.Name == seedName {
			targetSeed = seed
			break
		}
	}

	if targetSeed == nil {
		return fmt.Errorf("seed file '%s' not found", seedName)
	}

	fmt.Printf("Running seed: %s\n", targetSeed.Name)

	if err := s.runSeed(targetSeed); err != nil {
		return fmt.Errorf("failed to run seed %s: %w", targetSeed.Name, err)
	}

	fmt.Printf("✅ Seeded: %s\n", targetSeed.Name)
	return nil
}

// runSeed executes a seed file
func (s *Seeder) runSeed(seed *Seed) error {
	if strings.TrimSpace(seed.SQL) == "" {
		return fmt.Errorf("seed file is empty")
	}

	// Execute in a transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Split SQL by semicolons and execute each statement
	statements := strings.Split(seed.SQL, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}

		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}

	return tx.Commit()
}

// ClearAll clears all data from tables (for testing)
func (s *Seeder) ClearAll() error {
	fmt.Println("Clearing all data...")

	// Get all table names
	tables := []string{
		"webauthn_credentials",
		"social_accounts", 
		"api_keys",
		"refresh_tokens",
		"users",
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Disable foreign key checks temporarily
	if _, err := tx.Exec("SET session_replication_role = replica;"); err != nil {
		return fmt.Errorf("failed to disable foreign key checks: %w", err)
	}

	// Clear each table
	for _, table := range tables {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			// Table might not exist, continue
			fmt.Printf("Warning: Failed to clear table %s: %v\n", table, err)
		} else {
			fmt.Printf("Cleared table: %s\n", table)
		}
	}

	// Re-enable foreign key checks
	if _, err := tx.Exec("SET session_replication_role = DEFAULT;"); err != nil {
		return fmt.Errorf("failed to re-enable foreign key checks: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Println("✅ All data cleared")
	return nil
}

// CreateSeed creates a new seed file
func (s *Seeder) CreateSeed(name string) error {
	timestamp := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s.sql", timestamp, name)
	filePath := filepath.Join(s.seedsDir, filename)

	template := fmt.Sprintf(`-- Seed: %s
-- Created: %s

-- Insert your seed data here
-- Example:
-- INSERT INTO users (id, username, email, password_hash) VALUES 
--   ('123e4567-e89b-12d3-a456-426614174000', 'testuser', 'test@example.com', '$2a$12$...');

`, name, time.Now().Format("2006-01-02 15:04:05"))

	if err := os.WriteFile(filePath, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to create seed file: %w", err)
	}

	fmt.Printf("Created seed file: %s\n", filePath)
	return nil
}