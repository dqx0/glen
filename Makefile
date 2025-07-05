# Glen ID Platform Makefile

.PHONY: test test-unit test-integration build dev clean setup-deps

# テスト関連
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	cd services/auth-service && go test -v ./...
	cd services/user-service && go test -v ./...
	cd services/api-gateway && go test -v ./...
	cd shared && go test -v ./...

test-integration:
	@echo "Running integration tests..."
	cd services/auth-service && go test -v -tags=integration ./...
	cd services/user-service && go test -v -tags=integration ./...

test-coverage:
	@echo "Running tests with coverage..."
	cd services/auth-service && go test -v -coverprofile=coverage.out ./...
	cd services/user-service && go test -v -coverprofile=coverage.out ./...
	cd services/api-gateway && go test -v -coverprofile=coverage.out ./...

# ビルド
build:
	cd services/auth-service && go build -o ../../bin/auth-service ./cmd/server
	cd services/user-service && go build -o ../../bin/user-service ./cmd/server
	cd services/api-gateway && go build -o ../../bin/api-gateway ./cmd/server

# 開発環境
dev:
	docker-compose -f infrastructure/docker/docker-compose.dev.yml up -d

dev-stop:
	docker-compose -f infrastructure/docker/docker-compose.dev.yml down

# 依存関係インストール
setup-deps:
	cd services/auth-service && go mod download
	cd services/user-service && go mod download
	cd services/api-gateway && go mod download
	cd shared && go mod download

# クリーンアップ
clean:
	rm -rf bin/
	cd services/auth-service && go clean
	cd services/user-service && go clean
	cd services/api-gateway && go clean

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