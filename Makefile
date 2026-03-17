VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)
BINARY := argus

.PHONY: all build test clean lint run

all: test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/argus/

test:
	go test ./... -count=1 -timeout 30s

test-verbose:
	go test ./... -count=1 -timeout 30s -v

test-cover:
	go test ./... -count=1 -timeout 30s -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe coverage.out coverage.html

run: build
	./$(BINARY) -config configs/argus.json

cross-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/argus/

cross-darwin:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./cmd/argus/

cross-all: cross-linux cross-darwin build
