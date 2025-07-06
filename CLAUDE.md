# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Glen is a WebAuthn-based identity service built with Go microservices architecture. The project follows Test-Driven Development (TDD) principles and is designed to run on GCP within free tier limits.

## Development Commands

### Testing
```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run tests with coverage
make test-coverage

# Run tests for specific service
cd services/user-service && go test -v ./...
cd services/auth-service && go test -v ./...
```

### Building
```bash
# Build all services
make build

# Build specific service
cd services/user-service && go build -o ../../bin/user-service ./cmd/server
```

### Development Environment
```bash
# Setup dependencies
make setup-deps

# Start local development environment
make dev

# Stop development environment
make dev-stop
```

### Database
```bash
# Run database migrations
make db-migrate

# Rollback last migration
make db-rollback
```

### Code Quality
```bash
# Run linter
make lint

# Clean build artifacts
make clean
```

## Architecture

### Service Structure
```
services/
├── user-service/        # User management, registration, WebAuthn (✅ Complete)
├── auth-service/        # JWT tokens, API keys, refresh tokens (✅ Complete)
├── social-service/      # OAuth2 social logins (🚧 Partial)
└── api-gateway/         # Request routing and aggregation (⏸️ Not started)
```

### Current Implementation Status
- **User Service**: Fully implemented with comprehensive tests
- **Auth Service**: Fully implemented with JWT and token management
- **Social Service**: Models and OAuth2 service implemented, missing HTTP layer
- **API Gateway**: Not implemented

### Database Design
- **PostgreSQL** for production with separate databases per service
- **SQLite** for testing (in-memory)
- Schema located in `schema.sql` with comprehensive table design
- Support for WebAuthn credentials, social accounts, API tokens, and future RBAC

## Go Module Structure

All services use the module pattern `github.com/dqx0/glen/[service-name]`:
- `github.com/dqx0/glen/user-service`
- `github.com/dqx0/glen/auth-service` 
- `github.com/dqx0/glen/social-service`
- `github.com/dqx0/glen/api-gateway`
- `github.com/dqx0/glen/shared`

## Code Architecture Patterns

### Service Layer Pattern
Each service follows the same clean architecture:
```
internal/
├── models/        # Domain models and business logic
├── repository/    # Data access layer
├── service/       # Business logic layer
└── handlers/      # HTTP handlers
```

### Dependency Injection
Services use constructor injection pattern:
```go
// Repository -> Service -> Handler
repo := repository.NewUserRepository(db)
service := service.NewUserService(repo)
handler := handlers.NewUserHandler(service)
```

### Error Handling
Consistent error response format:
```go
{
  "success": false,
  "error": "error message"
}
```

## Testing Patterns

### Test Structure
- **Unit Tests**: Each layer has dedicated test files
- **Mocks**: Uses `testify/mock` for service layer testing
- **Table-driven Tests**: Comprehensive test cases for all scenarios
- **HTTP Testing**: Uses `httptest` for handler testing

### Test Database
- SQLite in-memory database for repository tests
- Database cleanup between tests
- Fixtures for consistent test data

## Security Implementation

### Authentication Methods
1. **WebAuthn** (Primary): Biometric/hardware key authentication
2. **Password** (Fallback): bcrypt hashed passwords
3. **Social Login** (In Progress): Google, GitHub, Discord OAuth2

### Token Management
- **JWT Access Tokens**: 15-minute expiry, RS256 signed
- **Refresh Tokens**: 30-day expiry, database stored with rotation
- **API Keys**: Persistent tokens with scope limitations

### Security Best Practices
- All passwords hashed with bcrypt
- JWT tokens signed with RSA keys
- API keys are hashed before storage
- Database prepared statements prevent SQL injection

## API Design

### Current Endpoints

**User Service (Port 8080):**
- `POST /api/v1/users/register` - User registration
- `POST /api/v1/users/login` - User login
- `GET /api/v1/users` - Get user details
- `GET /health` - Health check

**Auth Service (Port 8081):**
- `POST /api/v1/auth/login` - Login and token generation
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/api-keys` - API key creation
- `POST /api/v1/auth/revoke` - Token revocation
- `GET /api/v1/auth/tokens` - List user tokens
- `POST /api/v1/auth/validate-api-key` - API key validation

## Development Environment

### Go Version
- **Version**: 1.24.4
- **Installation**: `~/local/go/bin`
- **PATH**: `export PATH=$PATH:~/local/go/bin`

### Key Dependencies
- `github.com/stretchr/testify` - Testing framework
- `github.com/golang-jwt/jwt/v5` - JWT implementation
- `github.com/google/uuid` - UUID generation
- `github.com/lib/pq` - PostgreSQL driver
- `github.com/mattn/go-sqlite3` - SQLite driver for testing
- `golang.org/x/crypto` - Password hashing

## Infrastructure

### Local Development
- Docker Compose configuration for PostgreSQL
- Makefile for common development tasks
- Environment variables for configuration

### Production (Planned)
- GCP deployment within free tier limits
- Kubernetes configuration for container orchestration
- Cloud SQL for PostgreSQL
- Container Registry for image storage

## Important Notes

### TDD Development Flow
1. **Red**: Write failing test first
2. **Green**: Implement minimal code to pass test
3. **Refactor**: Improve code while keeping tests passing
4. **Commit**: Commit each complete feature with tests

### Code Quality Requirements
- All new code must have comprehensive tests
- Error handling is mandatory for all operations
- Context must be used for cancellation and timeouts
- JSON API responses must be consistent
- Follow existing code patterns and conventions

### Future Development Priorities
1. Complete social-service HTTP layer and database integration
2. Implement API gateway for service orchestration
3. Add multi-factor authentication (TOTP)
4. Implement role-based access control (RBAC)
5. Add monitoring and observability