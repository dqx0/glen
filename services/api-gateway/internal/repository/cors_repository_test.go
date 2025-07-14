package repository

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCORSRepository_AddOrigin(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	tests := []struct {
		name        string
		origin      string
		clientID    string
		expectError bool
		description string
	}{
		{
			name:        "Add valid HTTPS origin",
			origin:      "https://example.com",
			clientID:    "client_123",
			expectError: false,
			description: "Should successfully add HTTPS origin",
		},
		{
			name:        "Add localhost origin",
			origin:      "http://localhost:3000",
			clientID:    "client_456",
			expectError: false,
			description: "Should successfully add localhost origin",
		},
		{
			name:        "Add origin with port",
			origin:      "https://api.example.com:8443",
			clientID:    "client_789",
			expectError: false,
			description: "Should successfully add origin with custom port",
		},
		{
			name:        "Duplicate origin same client",
			origin:      "https://example.com",
			clientID:    "client_123",
			expectError: false,
			description: "Should handle duplicate origin for same client gracefully",
		},
		{
			name:        "Same origin different client",
			origin:      "https://shared.com",
			clientID:    "client_a",
			expectError: false,
			description: "Should allow same origin for different clients",
		},
		{
			name:        "Empty origin",
			origin:      "",
			clientID:    "client_empty",
			expectError: true,
			description: "Should reject empty origin",
		},
		{
			name:        "Empty client ID",
			origin:      "https://valid.com",
			clientID:    "",
			expectError: true,
			description: "Should reject empty client ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.AddOrigin(ctx, tt.origin, tt.clientID)
			
			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				
				// Verify origin was added
				origins, err := repo.GetAllOrigins(ctx)
				require.NoError(t, err)
				
				found := false
				for _, origin := range origins {
					if origin == tt.origin {
						found = true
						break
					}
				}
				assert.True(t, found, "Origin should be found after adding: %s", tt.origin)
			}
		})
	}

	// Test same origin for different clients
	t.Run("Same origin different clients", func(t *testing.T) {
		origin := "https://shared.com"
		
		err1 := repo.AddOrigin(ctx, origin, "client_b")
		require.NoError(t, err1)
		
		err2 := repo.AddOrigin(ctx, origin, "client_c") 
		require.NoError(t, err2)
		
		// Should have the origin (but may have multiple entries)
		origins, err := repo.GetAllOrigins(ctx)
		require.NoError(t, err)
		
		count := 0
		for _, o := range origins {
			if o == origin {
				count++
			}
		}
		assert.GreaterOrEqual(t, count, 1, "Origin should be present for multiple clients")
	})
}

func TestCORSRepository_RemoveOrigin(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	// Setup test data
	testOrigins := []struct {
		origin   string
		clientID string
	}{
		{"https://example.com", "client_1"},
		{"https://app.com", "client_2"},
		{"https://shared.com", "client_1"},
		{"https://shared.com", "client_2"},
	}

	for _, to := range testOrigins {
		err := repo.AddOrigin(ctx, to.origin, to.clientID)
		require.NoError(t, err)
	}

	tests := []struct {
		name         string
		origin       string
		expectError  bool
		shouldRemove bool
		description  string
	}{
		{
			name:         "Remove existing origin",
			origin:       "https://example.com",
			expectError:  false,
			shouldRemove: true,
			description:  "Should successfully remove existing origin",
		},
		{
			name:         "Remove shared origin",
			origin:       "https://shared.com",
			expectError:  false,
			shouldRemove: true,
			description:  "Should remove shared origin (all instances)",
		},
		{
			name:         "Remove non-existent origin",
			origin:       "https://nonexistent.com",
			expectError:  false,
			shouldRemove: false,
			description:  "Should handle non-existent origin gracefully",
		},
		{
			name:         "Remove empty origin",
			origin:       "",
			expectError:  true,
			shouldRemove: false,
			description:  "Should reject empty origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get initial origins
			initialOrigins, err := repo.GetAllOrigins(ctx)
			require.NoError(t, err)

			err = repo.RemoveOrigin(ctx, tt.origin)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)

				// Verify removal
				finalOrigins, err := repo.GetAllOrigins(ctx)
				require.NoError(t, err)

				if tt.shouldRemove {
					// Origin should not be in final list
					found := false
					for _, origin := range finalOrigins {
						if origin == tt.origin {
							found = true
							break
						}
					}
					assert.False(t, found, "Origin should be removed: %s", tt.origin)
				} else {
					// Number of origins should be the same
					assert.Equal(t, len(initialOrigins), len(finalOrigins), 
						"Origin count should be unchanged for non-existent origin")
				}
			}
		})
	}
}

func TestCORSRepository_GetAllOrigins(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	t.Run("Empty database", func(t *testing.T) {
		origins, err := repo.GetAllOrigins(ctx)
		require.NoError(t, err)
		assert.Empty(t, origins, "Should return empty slice for empty database")
	})

	t.Run("With origins", func(t *testing.T) {
		// Add test origins
		testOrigins := []string{
			"https://example.com",
			"https://app.com", 
			"http://localhost:3000",
			"https://api.domain.com:8443",
		}

		for i, origin := range testOrigins {
			err := repo.AddOrigin(ctx, origin, fmt.Sprintf("client_%d", i))
			require.NoError(t, err)
		}

		// Get all origins
		origins, err := repo.GetAllOrigins(ctx)
		require.NoError(t, err)

		// Verify all origins are present (as unique values)
		originSet := make(map[string]bool)
		for _, origin := range origins {
			originSet[origin] = true
		}

		for _, expectedOrigin := range testOrigins {
			assert.True(t, originSet[expectedOrigin], 
				"Expected origin should be present: %s", expectedOrigin)
		}
	})
}

func TestCORSRepository_RemoveOriginsByClientID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	// Setup test data
	testData := []struct {
		origin   string
		clientID string
	}{
		{"https://client1-app.com", "client_1"},
		{"https://client1-api.com", "client_1"},
		{"https://client2-app.com", "client_2"},
		{"https://shared.com", "client_1"},
		{"https://shared.com", "client_2"},
		{"https://other.com", "client_3"},
	}

	for _, td := range testData {
		err := repo.AddOrigin(ctx, td.origin, td.clientID)
		require.NoError(t, err)
	}

	tests := []struct {
		name              string
		clientID          string
		expectError       bool
		expectedRemaining []string
		description       string
	}{
		{
			name:        "Remove all origins for client_1",
			clientID:    "client_1",
			expectError: false,
			expectedRemaining: []string{
				"https://client2-app.com",
				"https://shared.com", // Should remain for client_2
				"https://other.com",
			},
			description: "Should remove only origins for client_1",
		},
		{
			name:        "Remove origins for non-existent client",
			clientID:    "client_nonexistent",
			expectError: false,
			expectedRemaining: []string{
				"https://client2-app.com",
				"https://shared.com",
				"https://other.com",
			},
			description: "Should handle non-existent client gracefully",
		},
		{
			name:              "Remove origins with empty client ID",
			clientID:          "",
			expectError:       true,
			expectedRemaining: nil,
			description:       "Should reject empty client ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.RemoveOriginsByClientID(ctx, tt.clientID)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)

				if tt.expectedRemaining != nil {
					// Verify remaining origins
					remainingOrigins, err := repo.GetAllOrigins(ctx)
					require.NoError(t, err)

					remainingSet := make(map[string]bool)
					for _, origin := range remainingOrigins {
						remainingSet[origin] = true
					}

					for _, expectedOrigin := range tt.expectedRemaining {
						assert.True(t, remainingSet[expectedOrigin],
							"Expected origin should remain: %s", expectedOrigin)
					}
				}
			}
		})
	}
}

func TestCORSRepository_GetOriginsByClientID(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	// Setup test data
	client1Origins := []string{"https://app1.com", "https://api1.com"}
	client2Origins := []string{"https://app2.com"}
	sharedOrigin := "https://shared.com"

	for _, origin := range client1Origins {
		err := repo.AddOrigin(ctx, origin, "client_1")
		require.NoError(t, err)
	}

	for _, origin := range client2Origins {
		err := repo.AddOrigin(ctx, origin, "client_2")
		require.NoError(t, err)
	}

	// Add shared origin for both clients
	err := repo.AddOrigin(ctx, sharedOrigin, "client_1")
	require.NoError(t, err)
	err = repo.AddOrigin(ctx, sharedOrigin, "client_2")
	require.NoError(t, err)

	tests := []struct {
		name            string
		clientID        string
		expectedOrigins []string
		expectError     bool
		description     string
	}{
		{
			name:     "Get origins for client_1",
			clientID: "client_1",
			expectedOrigins: []string{
				"https://app1.com",
				"https://api1.com", 
				"https://shared.com",
			},
			expectError: false,
			description: "Should return all origins for client_1",
		},
		{
			name:     "Get origins for client_2",
			clientID: "client_2",
			expectedOrigins: []string{
				"https://app2.com",
				"https://shared.com",
			},
			expectError: false,
			description: "Should return all origins for client_2",
		},
		{
			name:            "Get origins for non-existent client",
			clientID:        "client_nonexistent",
			expectedOrigins: []string{},
			expectError:     false,
			description:     "Should return empty slice for non-existent client",
		},
		{
			name:            "Get origins with empty client ID",
			clientID:        "",
			expectedOrigins: nil,
			expectError:     true,
			description:     "Should reject empty client ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origins, err := repo.GetOriginsByClientID(ctx, tt.clientID)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)

				if tt.expectedOrigins != nil {
					assert.ElementsMatch(t, tt.expectedOrigins, origins, tt.description)
				}
			}
		})
	}
}

func TestCORSRepository_ConcurrentOperations(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewCORSRepository(db.DB)
	ctx := context.Background()

	// Test concurrent adds
	t.Run("Concurrent adds", func(t *testing.T) {
		const numGoroutines = 10
		done := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				origin := fmt.Sprintf("https://concurrent%d.com", id)
				clientID := fmt.Sprintf("client_%d", id)
				done <- repo.AddOrigin(ctx, origin, clientID)
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < numGoroutines; i++ {
			err := <-done
			assert.NoError(t, err, "Concurrent add should succeed")
		}

		// Verify all origins were added
		origins, err := repo.GetAllOrigins(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(origins), numGoroutines,
			"Should have at least %d origins after concurrent adds", numGoroutines)
	})
}

// setupTestDB creates a test database connection and returns cleanup function
func setupTestDB(t *testing.T) (*sqlx.DB, func()) {
	// Skip test if no database available
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping database tests")
	}

	db, err := sqlx.Connect("postgres", dbURL)
	require.NoError(t, err, "Failed to connect to test database")

	// Create test table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS cors_dynamic_origins (
			id SERIAL PRIMARY KEY,
			origin VARCHAR(255) NOT NULL,
			oauth2_client_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(origin, oauth2_client_id)
		)
	`)
	require.NoError(t, err, "Failed to create test table")

	// Create index
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_cors_origins_origin ON cors_dynamic_origins(origin);
		CREATE INDEX IF NOT EXISTS idx_cors_origins_client_id ON cors_dynamic_origins(oauth2_client_id);
	`)
	require.NoError(t, err, "Failed to create indexes")

	cleanup := func() {
		// Clean up test data
		_, err := db.Exec("TRUNCATE TABLE cors_dynamic_origins")
		if err != nil {
			t.Logf("Failed to cleanup test data: %v", err)
		}
		db.Close()
	}

	return db, cleanup
}