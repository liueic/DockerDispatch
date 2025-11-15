.PHONY: build test clean docker-build docker-run docker-stop fmt lint

# Build the application
build:
	go build -o bin/mirror-registry ./cmd

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Build Docker image
docker-build:
	docker build -t mirror-registry:latest .

# Run with Docker Compose
docker-up:
	docker-compose up -d

# Stop Docker Compose
docker-down:
	docker-compose down

# View Docker Compose logs
docker-logs:
	docker-compose logs -f

# Run locally with development config
run-dev:
	go run ./cmd/main.go

# Download dependencies
deps:
	go mod download
	go mod tidy

# Generate go.sum
mod-tidy:
	go mod tidy

# All checks before commit
pre-commit: fmt lint test