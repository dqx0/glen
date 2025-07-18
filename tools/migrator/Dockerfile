FROM golang:1.24.4-alpine AS builder

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrator ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates postgresql-client

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/migrator .

# Copy migration files and scripts
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/seeds ./seeds
COPY --from=builder /app/run-migrations.sh .

# Make executables
RUN chmod +x ./migrator ./run-migrations.sh

CMD ["./run-migrations.sh"]