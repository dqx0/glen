package migrations

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

// Migration represents a database migration
type Migration struct {
	Version     string
	Name        string
	UpSQL       string
	DownSQL     string
	Applied     bool
	AppliedAt   *time.Time
}

// Migrator handles database migrations
type Migrator struct {
	db           *database.DB
	migrationsDir string
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *database.DB, migrationsDir string) *Migrator {
	return &Migrator{
		db:           db,
		migrationsDir: migrationsDir,
	}
}

// LoadMigrations loads all migrations from the migrations directory
func (m *Migrator) LoadMigrations() ([]*Migration, error) {
	var migrations []*Migration

	err := filepath.WalkDir(m.migrationsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		migration, err := m.parseMigrationFile(path)
		if err != nil {
			return fmt.Errorf("failed to parse migration file %s: %w", path, err)
		}

		migrations = append(migrations, migration)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	// Mark applied migrations
	appliedVersions, err := m.db.GetAppliedMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedMap := make(map[string]bool)
	for _, version := range appliedVersions {
		appliedMap[version] = true
	}

	for _, migration := range migrations {
		migration.Applied = appliedMap[migration.Version]
	}

	return migrations, nil
}

// parseMigrationFile parses a migration file and extracts up/down SQL
func (m *Migrator) parseMigrationFile(filePath string) (*Migration, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	filename := filepath.Base(filePath)
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid migration filename format: %s", filename)
	}

	version := parts[0]
	name := strings.TrimSuffix(parts[1], ".sql")

	// Split content by -- +migrate Down
	sections := strings.Split(string(content), "-- +migrate Down")
	
	migration := &Migration{
		Version: version,
		Name:    name,
		UpSQL:   strings.TrimSpace(sections[0]),
	}

	if len(sections) > 1 {
		migration.DownSQL = strings.TrimSpace(sections[1])
	}

	return migration, nil
}

// Up runs all pending migrations
func (m *Migrator) Up() error {
	if err := m.db.CreateMigrationTable(); err != nil {
		return err
	}

	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if migration.Applied {
			continue
		}

		fmt.Printf("Applying migration %s: %s\n", migration.Version, migration.Name)

		if err := m.applyMigration(migration); err != nil {
			m.db.MarkMigrationDirty(migration.Version)
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}

		if err := m.db.MarkMigrationApplied(migration.Version); err != nil {
			return fmt.Errorf("failed to mark migration as applied: %w", err)
		}

		fmt.Printf("✅ Applied migration %s\n", migration.Version)
	}

	fmt.Println("All migrations applied successfully!")
	return nil
}

// Down rolls back the last migration
func (m *Migrator) Down() error {
	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	// Find the last applied migration
	var lastMigration *Migration
	for i := len(migrations) - 1; i >= 0; i-- {
		if migrations[i].Applied {
			lastMigration = migrations[i]
			break
		}
	}

	if lastMigration == nil {
		fmt.Println("No migrations to roll back")
		return nil
	}

	if lastMigration.DownSQL == "" {
		return fmt.Errorf("migration %s has no down SQL", lastMigration.Version)
	}

	fmt.Printf("Rolling back migration %s: %s\n", lastMigration.Version, lastMigration.Name)

	if err := m.rollbackMigration(lastMigration); err != nil {
		return fmt.Errorf("failed to rollback migration %s: %w", lastMigration.Version, err)
	}

	if err := m.db.RemoveMigration(lastMigration.Version); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	fmt.Printf("✅ Rolled back migration %s\n", lastMigration.Version)
	return nil
}

// Status shows the current migration status
func (m *Migrator) Status() error {
	if err := m.db.CreateMigrationTable(); err != nil {
		return err
	}

	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	fmt.Println("Migration Status:")
	fmt.Println("=================")

	if len(migrations) == 0 {
		fmt.Println("No migrations found")
		return nil
	}

	for _, migration := range migrations {
		status := "❌ Pending"
		if migration.Applied {
			status = "✅ Applied"
		}

		fmt.Printf("%s %s: %s\n", status, migration.Version, migration.Name)
	}

	return nil
}

// applyMigration executes the up SQL for a migration
func (m *Migrator) applyMigration(migration *Migration) error {
	if migration.UpSQL == "" {
		return fmt.Errorf("migration has no up SQL")
	}

	// Execute in a transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(migration.UpSQL); err != nil {
		return fmt.Errorf("failed to execute up SQL: %w", err)
	}

	return tx.Commit()
}

// rollbackMigration executes the down SQL for a migration
func (m *Migrator) rollbackMigration(migration *Migration) error {
	if migration.DownSQL == "" {
		return fmt.Errorf("migration has no down SQL")
	}

	// Execute in a transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(migration.DownSQL); err != nil {
		return fmt.Errorf("failed to execute down SQL: %w", err)
	}

	return tx.Commit()
}

// CreateMigration creates a new migration file
func (m *Migrator) CreateMigration(name string) error {
	version := time.Now().Format("20060102150405")
	filename := fmt.Sprintf("%s_%s.sql", version, name)
	filePath := filepath.Join(m.migrationsDir, filename)

	template := fmt.Sprintf(`-- Migration: %s
-- Created: %s

-- +migrate Up


-- +migrate Down

`, name, time.Now().Format("2006-01-02 15:04:05"))

	if err := os.WriteFile(filePath, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to create migration file: %w", err)
	}

	fmt.Printf("Created migration file: %s\n", filePath)
	return nil
}