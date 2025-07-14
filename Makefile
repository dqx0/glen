# Glen ID Platform Makefile

.PHONY: test test-unit test-integration test-e2e test-e2e-up test-e2e-down test-e2e-logs build docker-build docker-build-parallel docker-clean docker-prune dev dev-stop dev-logs dev-status dev-restart dev-services dev-services-stop clean clean-all setup-deps quickstart fullstack fullstack-stop migrator-build migrate-up migrate-down migrate-status migrate-create seed-all seed seed-create db-clear db-reset db-setup help

# テスト関連
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	cd services/auth-service && go test -v ./...
	cd services/user-service && go test -v ./...
	cd services/social-service && go test -v ./...
	cd services/api-gateway && go test -v ./...

test-integration:
	@echo "Running integration tests..."
	cd services/auth-service && go test -v -tags=integration ./...
	cd services/user-service && go test -v -tags=integration ./...

test-e2e:
	@echo "🧪 Running E2E tests..."
	@echo "🐳 Building test images..."
	@$(MAKE) docker-build
	@echo "🚀 Starting test environment..."
	docker-compose -f infrastructure/docker/docker-compose.test.yml up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 15
	@echo "🧪 Running E2E test suite..."
	cd tests/e2e && go test -v ./...
	@echo "🛑 Stopping test environment..."
	docker-compose -f infrastructure/docker/docker-compose.test.yml down
	@echo "✅ E2E tests completed"

test-e2e-up:
	@echo "🚀 Starting E2E test environment (persistent)..."
	@$(MAKE) docker-build
	docker-compose -f infrastructure/docker/docker-compose.test.yml up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 15
	@echo "✅ E2E environment ready!"
	@echo "📍 API Gateway: http://localhost:8080"
	@echo "🧪 Run tests: cd tests/e2e && go test -v ./..."
	@echo "🛑 Stop environment: make test-e2e-down"

test-e2e-down:
	@echo "🛑 Stopping E2E test environment..."
	docker-compose -f infrastructure/docker/docker-compose.test.yml down
	@echo "✅ E2E environment stopped"

test-e2e-logs:
	@echo "📄 Showing E2E test environment logs..."
	docker-compose -f infrastructure/docker/docker-compose.test.yml logs -f

test-coverage:
	@echo "Running tests with coverage..."
	cd services/auth-service && go test -v -coverprofile=coverage.out ./...
	cd services/user-service && go test -v -coverprofile=coverage.out ./...
	cd services/api-gateway && go test -v -coverprofile=coverage.out ./...

# ビルド
build:
	@echo "🔨 Building Go binaries..."
	@mkdir -p bin
	cd services/auth-service && go build -o ../../bin/auth-service ./cmd/server
	cd services/user-service && go build -o ../../bin/user-service ./cmd/server
	cd services/social-service && go build -o ../../bin/social-service ./cmd/server
	cd services/api-gateway && go build -o ../../bin/api-gateway ./cmd/server
	@echo "✅ Build completed"


docker-build-parallel:
	@echo "🐳 Building Docker images in parallel..."
	@docker build -t glen/auth-service:latest -f services/auth-service/Dockerfile services/auth-service & \
	docker build -t glen/user-service:latest -f services/user-service/Dockerfile services/user-service & \
	docker build -t glen/social-service:latest -f services/social-service/Dockerfile services/social-service & \
	docker build -t glen/api-gateway:latest -f services/api-gateway/Dockerfile services/api-gateway & \
	wait
	@echo "✅ Docker images built (parallel)"

docker-clean:
	@echo "🧹 Cleaning Docker images..."
	docker rmi glen/auth-service:latest glen/user-service:latest glen/social-service:latest glen/api-gateway:latest 2>/dev/null || true
	@echo "✅ Docker images cleaned"

docker-prune:
	@echo "🧹 Pruning Docker system..."
	docker system prune -f
	@echo "✅ Docker system pruned"

# Docker環境管理
dev:
	@echo "🚀 Starting development environment..."
	@echo "📊 Starting PostgreSQL and Redis..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml up -d
	@echo "⏳ Waiting for database to be ready..."
	@sleep 5
	@echo "✅ Development environment is ready!"
	@echo ""
	@echo "📍 Available services:"
	@echo "   - PostgreSQL: localhost:5432 (glen_dev/glen_dev/glen_dev_pass)"
	@echo "   - Redis: localhost:6379"
	@echo ""
	@echo "🔧 Next steps:"
	@echo "   - Run services: make dev-services"
	@echo "   - View logs: make dev-logs"
	@echo "   - Stop all: make dev-stop"

dev-stop:
	@echo "🛑 Stopping development environment..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml down
	@echo "✅ Development environment stopped"

dev-logs:
	@echo "📄 Showing development environment logs..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml logs -f

dev-status:
	@echo "📊 Development environment status:"
	docker-compose -f infrastructure/docker/docker-compose.dev.yml ps

dev-restart:
	@echo "🔄 Restarting development environment..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml restart
	@echo "✅ Development environment restarted"

# サービス起動（開発用）
dev-services:
	@echo "🚀 Starting all services in development mode..."
	@echo "Starting user-service..."
	cd services/user-service && PORT=8082 DB_HOST=localhost DB_NAME=glen_dev DB_USER=glen_dev DB_PASSWORD=glen_dev_pass go run ./cmd/server &
	@echo "Starting auth-service..."
	cd services/auth-service && PORT=8081 DB_HOST=localhost DB_NAME=glen_dev DB_USER=glen_dev DB_PASSWORD=glen_dev_pass go run ./cmd/server &
	@echo "Starting social-service..."
	cd services/social-service && PORT=8083 DB_HOST=localhost DB_NAME=glen_dev DB_USER=glen_dev DB_PASSWORD=glen_dev_pass go run ./cmd/server &
	@echo "Starting api-gateway..."
	cd services/api-gateway && PORT=8080 USER_SERVICE_URL=http://localhost:8082 AUTH_SERVICE_URL=http://localhost:8081 SOCIAL_SERVICE_URL=http://localhost:8083 go run ./cmd/server &
	@echo ""
	@echo "✅ All services started!"
	@echo "📍 API Gateway: http://localhost:8080"
	@echo "📍 User Service: http://localhost:8082"
	@echo "📍 Auth Service: http://localhost:8081"
	@echo "📍 Social Service: http://localhost:8083"

dev-services-stop:
	@echo "🛑 Stopping all Go services..."
	@pkill -f "go run.*glen.*server" || true
	@echo "✅ All services stopped"

# 依存関係インストール
setup-deps:
	cd services/auth-service && go mod download
	cd services/user-service && go mod download
	cd services/api-gateway && go mod download
	cd shared && go mod download

# クリーンアップ
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	cd services/auth-service && go clean
	cd services/user-service && go clean
	cd services/social-service && go clean
	cd services/api-gateway && go clean
	@echo "✅ Clean completed"

clean-all: clean docker-clean
	@echo "🧹 Full cleanup completed"

# クイックスタート
quickstart:
	@echo "🚀 Glen ID Platform - Quick Start"
	@echo ""
	@echo "1️⃣ Starting development environment..."
	@$(MAKE) dev
	@echo ""
	@echo "2️⃣ Setting up dependencies..."
	@$(MAKE) setup-deps
	@echo ""
	@echo "3️⃣ Building Docker images..."
	@$(MAKE) docker-build
	@echo ""
	@echo "✅ Quick start completed!"
	@echo ""
	@echo "📋 Next steps:"
	@echo "  - Start services: make dev-services"
	@echo "  - Run tests: make test-unit"
	@echo "  - Run E2E tests: make test-e2e"
	@echo "  - View help: make help"

# フルスタック起動（Docker Compose）
fullstack-docker:
	@echo "🌟 Starting full Glen ID Platform stack with Docker..."
	@echo "📦 Installing frontend dependencies..."
	@$(MAKE) frontend-install
	@echo "🎨 Building frontend..."
	@$(MAKE) frontend-build
	@echo "🐳 Building and starting all services..."
	docker-compose -f infrastructure/docker/docker-compose.fullstack.yml up --build -d
	@echo ""
	@echo "⏳ Waiting for all services to be ready..."
	@sleep 30
	@echo ""
	@echo "✅ Full stack is running!"
	@echo "📍 Access points:"
	@echo "  - Frontend: http://localhost:3000"
	@echo "  - API Gateway: http://localhost:8080"
	@echo "  - User Service: http://localhost:8082"
	@echo "  - Auth Service: http://localhost:8081"
	@echo "  - Social Service: http://localhost:8083"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis: localhost:6379"
	@echo ""
	@echo "🛑 To stop: make fullstack-docker-stop"

# フルスタック停止（Docker Compose）
fullstack-docker-stop:
	@echo "🛑 Stopping full Glen ID Platform stack..."
	docker compose -f infrastructure/docker/docker-compose.fullstack.yml down -v
	@echo "✅ Full stack stopped"

# フルスタックログ表示
fullstack-docker-logs:
	@echo "📄 Showing full stack logs..."
	docker-compose -f infrastructure/docker/docker-compose.fullstack.yml logs -f

# フルスタック状態確認
fullstack-docker-status:
	@echo "📊 Full stack status:"
	docker-compose -f infrastructure/docker/docker-compose.fullstack.yml ps

# ヘルプ
help:
	@echo "🚀 Glen ID Platform - Available Commands"
	@echo ""
	@echo "⚡ Quick Start:"
	@echo "  make quickstart         - Initial setup (recommended)"
	@echo "  make fullstack          - Start full stack"
	@echo "  make fullstack-stop     - Stop full stack"
	@echo ""
	@echo "📋 Testing:"
	@echo "  make test-unit          - Run all unit tests"
	@echo "  make test-e2e           - Run E2E tests (full cycle)"
	@echo "  make test-e2e-up        - Start E2E environment (persistent)"
	@echo "  make test-e2e-down      - Stop E2E environment"
	@echo "  make test-e2e-logs      - Show E2E environment logs"
	@echo "  make test-coverage      - Run tests with coverage"
	@echo ""
	@echo "🔨 Building:"
	@echo "  make build              - Build Go binaries"
	@echo "  make docker-build       - Build Docker images"
	@echo "  make docker-build-parallel - Build Docker images (parallel)"
	@echo ""
	@echo "🐳 Development Environment:"
	@echo "  make dev                - Start PostgreSQL + Redis"
	@echo "  make dev-services       - Start all Go services"
	@echo "  make dev-stop           - Stop Docker environment"
	@echo "  make dev-services-stop  - Stop Go services"
	@echo "  make dev-logs           - Show development logs"
	@echo "  make dev-status         - Show environment status"
	@echo "  make dev-restart        - Restart environment"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make docker-clean       - Clean Docker images"
	@echo "  make docker-prune       - Prune Docker system"
	@echo "  make clean-all          - Full cleanup"
	@echo ""
	@echo "🗄️ Database:"
	@echo "  make db-migrate         - Run database migrations"
	@echo "  make db-rollback        - Rollback last migration"
	@echo ""
	@echo "☸️ Kubernetes:"
	@echo "  make k8s-deploy         - Deploy to Kubernetes"
	@echo "  make k8s-delete         - Delete from Kubernetes"
	@echo ""
	@echo "🔍 Other:"
	@echo "  make lint               - Run linters"
	@echo "  make setup-deps         - Download dependencies"
	@echo "  make help               - Show this help"

# データベース関連
db-migrate:
	migrate -path ./infrastructure/migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" up

db-rollback:
	migrate -path ./infrastructure/migrations -database "postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable" down 1

# K8s関連
k8s-deploy:
	kubectl apply -f infrastructure/k8s/

k8s-delete:
	kubectl delete -f infrastructure/k8s/

# リント
lint:
	cd services/auth-service && golangci-lint run
	cd services/user-service && golangci-lint run
	cd services/api-gateway && golangci-lint run

# フロントエンド関連
frontend-install:
	@echo "📦 Installing frontend dependencies..."
	cd frontend && npm install
	@echo "✅ Frontend dependencies installed"

frontend-build:
	@echo "🎨 Building frontend..."
	cd frontend && npm run build
	@echo "✅ Frontend built"

frontend-dev:
	@echo "🎨 Starting frontend development server..."
	cd frontend && npm run dev

# DB + Redis + Frontend 起動
debug:
	@echo "🚀 Starting database, Redis, and frontend..."
	@echo "📊 Starting PostgreSQL and Redis..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml up -d
	@echo "⏳ Waiting for database to be ready..."
	@sleep 5
	@echo "📦 Installing frontend dependencies..."
	cd frontend && npm install
	@echo "🎨 Starting frontend development server..."
	cd frontend && npm run dev &
	@echo ""
	@echo "✅ All services started!"
	@echo "📍 Available services:"
	@echo "   - Frontend: http://localhost:3000 (or check terminal output)"
	@echo "   - PostgreSQL: localhost:5432 (glen_dev/glen_dev/glen_dev_pass)"
	@echo "   - Redis: localhost:6379"
	@echo ""
	@echo "🛑 To stop: make debug-stop"

# DB + Redis + Frontend 停止
debug-stop:
	@echo "🛑 Stopping all services..."
	@echo "🛑 Stopping frontend..."
	@pkill -f "npm run dev" || true
	@echo "🛑 Stopping database and Redis..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml down
	@echo "✅ All services stopped"

frontend-docker-build:
	@echo "🐳 Building frontend Docker image..."
	docker build -t glen/frontend:latest -f frontend/Dockerfile frontend \
		--build-arg VITE_API_URL=https://api.glen.dqx0.com \
		--build-arg VITE_APP_NAME="Glen ID Platform" \
		--build-arg VITE_WEBAUTHN_ENABLED=true
	@echo "✅ Frontend Docker image built"

frontend-docker-build-prod:
	@echo "🐳 Building frontend Docker image for production..."
	docker build -t glen/frontend:production -f frontend/Dockerfile frontend \
		--build-arg VITE_API_URL=https://api.glen.dqx0.com \
		--build-arg VITE_APP_NAME="Glen ID Platform" \
		--build-arg VITE_WEBAUTHN_ENABLED=true
	@echo "✅ Frontend production Docker image built"

# Docker関連 (統合版)
docker-build:
	@echo "🐳 Building Docker images for Docker Hub..."
	docker build -t $(DOCKER_HUB_USERNAME)/glen-auth-service:latest -f services/auth-service/Dockerfile services/auth-service
	docker build -t $(DOCKER_HUB_USERNAME)/glen-user-service:latest -f services/user-service/Dockerfile services/user-service
	docker build -t $(DOCKER_HUB_USERNAME)/glen-social-service:latest -f services/social-service/Dockerfile services/social-service
	docker build -t $(DOCKER_HUB_USERNAME)/glen-api-gateway:latest -f services/api-gateway/Dockerfile services/api-gateway
	docker build -t $(DOCKER_HUB_USERNAME)/glen-frontend:latest -f frontend/Dockerfile frontend \
		--build-arg VITE_API_URL=https://api.glen.dqx0.com \
		--build-arg VITE_APP_NAME="Glen ID Platform" \
		--build-arg VITE_WEBAUTHN_ENABLED=true
	@echo "✅ All Docker images built for Docker Hub"

docker-push:
	@echo "🚀 Pushing Docker images to Docker Hub..."
	docker push $(DOCKER_HUB_USERNAME)/glen-auth-service:latest
	docker push $(DOCKER_HUB_USERNAME)/glen-user-service:latest
	docker push $(DOCKER_HUB_USERNAME)/glen-social-service:latest
	docker push $(DOCKER_HUB_USERNAME)/glen-api-gateway:latest
	docker push $(DOCKER_HUB_USERNAME)/glen-frontend:latest
	@echo "✅ All Docker images pushed to Docker Hub"

# マイグレーション関連
migrator-build:
	@echo "🔧 Building migrator..."
	cd tools/migrator && go build -o ../../bin/migrator ./cmd
	@echo "✅ Migrator built"

migrate-up: migrator-build
	@echo "⬆️ Running database migrations..."
	./bin/migrator -cmd=up -migrations-dir=tools/migrator/migrations

migrate-down: migrator-build
	@echo "⬇️ Rolling back last migration..."
	./bin/migrator -cmd=down -migrations-dir=tools/migrator/migrations

migrate-status: migrator-build
	@echo "📊 Checking migration status..."
	./bin/migrator -cmd=status -migrations-dir=tools/migrator/migrations

migrate-create: migrator-build
	@echo "📝 Creating new migration..."
	@if [ -z "$(NAME)" ]; then echo "Usage: make migrate-create NAME=migration_name"; exit 1; fi
	./bin/migrator -cmd=create -name=$(NAME) -migrations-dir=tools/migrator/migrations

seed-all: migrator-build
	@echo "🌱 Running all seed files..."
	./bin/migrator -cmd=seed-all -seeds-dir=tools/migrator/seeds

seed: migrator-build
	@echo "🌱 Running specific seed..."
	@if [ -z "$(NAME)" ]; then echo "Usage: make seed NAME=seed_name"; exit 1; fi
	./bin/migrator -cmd=seed -name=$(NAME) -seeds-dir=tools/migrator/seeds

seed-create: migrator-build
	@echo "📝 Creating new seed file..."
	@if [ -z "$(NAME)" ]; then echo "Usage: make seed-create NAME=seed_name"; exit 1; fi
	./bin/migrator -cmd=create-seed -name=$(NAME) -seeds-dir=tools/migrator/seeds

db-clear: migrator-build
	@echo "🧹 Clearing all database data..."
	./bin/migrator -cmd=clear

db-reset: db-clear migrate-up seed-all
	@echo "🔄 Database reset complete"

db-setup: migrate-up seed-all
	@echo "📊 Database setup complete"