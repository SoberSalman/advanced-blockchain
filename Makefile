# Makefile for Advanced Blockchain System

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
BINARY_NAME=advanced-blockchain
BINARY_UNIX=$(BINARY_NAME)_unix
MAIN_PATH=./cmd

# Build targets
.PHONY: all build clean test fmt vet run deps vendor update bootstrap

all: test build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v $(MAIN_PATH)

test:
	$(GOTEST) -v ./...

fmt:
	$(GOFMT) ./...

vet:
	$(GOVET) ./...

clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -rf ./data

run: build
	./$(BINARY_NAME)

# Run as validator node
run-validator: build
	./$(BINARY_NAME) --validator --miner --shard=0 --log-level=debug

# Run as regular node
run-node: build
	./$(BINARY_NAME) --shard=0 --log-level=debug

# Run as node in specific shard
run-shard1: build
	./$(BINARY_NAME) --shard=1 --log-level=debug

# Initialize dependencies
deps:
	$(GOMOD) tidy
	$(GOGET) -u

# Update dependencies
update:
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Create vendor directory
vendor:
	$(GOMOD) vendor

# Create multi-node bootstrap network (requires tmux)
bootstrap:
	@echo "Starting bootstrap node..."
	tmux new-session -d -s blockchain-net "$(MAKE) run-validator"
	@echo "Starting shard 0 node..."
	tmux split-window -h "sleep 2 && $(MAKE) run-node"
	@echo "Starting shard 1 node..."
	tmux split-window -v "sleep 3 && $(MAKE) run-shard1"
	@echo "Network started. Attach with: tmux attach-session -t blockchain-net"

# Cross compilation
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v $(MAIN_PATH)

# Docker targets
.PHONY: docker-build docker-run

docker-build:
	docker build -t advanced-blockchain:latest .

docker-run:
	docker run --rm -it advanced-blockchain:latest

# Build CLI and Dashboard
build-cli:
	$(GOBUILD) -o blockchain-cli -v ./cmd/cli

build-dashboard:
	$(GOBUILD) -o blockchain-dashboard -v ./cmd/dashboard

build-all: build build-cli build-dashboard

# Run with dashboard
run-with-dashboard: build
	./$(BINARY_NAME) --dashboard --api-port=8545

# Run CLI
run-cli: build-cli
	./blockchain-cli --node=http://localhost:8545

# Run dashboard separately
run-dashboard: build-dashboard
	./blockchain-dashboard --port=8080

# Complete demo setup (multiple terminals)
demo:
	@echo "Run these commands in separate terminals:"
	@echo "1. make run-with-dashboard"
	@echo "2. make run-cli"
	@echo "3. Open http://localhost:8080 in browser"
	@echo "4. Optional: Run additional nodes with different ports"