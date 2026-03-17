VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)
BINARY := argus

.PHONY: all build test clean lint run bench cover validate

all: lint test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/argus/
	@echo "Built $(BINARY) $(VERSION)"

test:
	go test ./... -count=1 -timeout 60s

test-verbose:
	go test ./... -count=1 -timeout 60s -v

test-race:
	go test ./... -count=1 -timeout 120s -race

cover:
	go test ./... -count=1 -timeout 60s -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | grep "^total:"
	@echo "Report: coverage.html"

bench:
	go test ./internal/inspection/ ./internal/masking/ ./internal/policy/ ./internal/ratelimit/ ./internal/pool/ ./internal/metrics/ -bench=. -benchmem

lint:
	go vet ./...

validate: build
	./$(BINARY) -config configs/argus.json -validate

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-* coverage.out coverage.html

run: build
	./$(BINARY) -config configs/argus.json

run-dev: build
	./$(BINARY) -config configs/argus-dev.json

docker:
	docker build -t argus:latest .

docker-up:
	docker compose up -d
	@echo "Waiting for databases to be healthy..."
	@sleep 15
	@echo "Services:"
	@echo "  PostgreSQL direct: localhost:35432"
	@echo "  MySQL direct:      localhost:33306"
	@echo "  MSSQL direct:      localhost:31433"
	@echo "  Argus PG proxy:    localhost:30100"
	@echo "  Argus MySQL proxy: localhost:30101"
	@echo "  Argus MSSQL proxy: localhost:30102"
	@echo "  Argus Admin/API:   localhost:30200"

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f argus

docker-status:
	docker compose ps

e2e: docker-up
	@echo "Running E2E basic tests..."
	bash scripts/test-e2e-full.sh

e2e-advanced: docker-up
	@echo "Running advanced E2E tests..."
	bash scripts/test-e2e-advanced.sh

e2e-all: docker-up
	@echo "Running all E2E tests..."
	bash scripts/test-e2e-full.sh
	bash scripts/test-e2e-advanced.sh

setup-mssql:
	bash scripts/setup-mssql.sh

cross-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/argus/
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 ./cmd/argus/

cross-darwin:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./cmd/argus/
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 ./cmd/argus/

cross-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINARY)-windows-amd64.exe ./cmd/argus/

cross-all: cross-linux cross-darwin cross-windows
	@echo "Cross-compilation complete"

stats:
	@echo "=== Project Stats ==="
	@echo "Go files: $$(find . -name '*.go' -not -path './.git/*' | wc -l)"
	@echo "Go LOC:   $$(find . -name '*.go' -not -path './.git/*' | xargs wc -l | tail -1)"
	@echo "Tests:    $$(go test ./... -v -count=1 -timeout 60s 2>&1 | grep -c '=== RUN')"
	@echo "Commits:  $$(git log --oneline | wc -l)"
	@ls -lh $(BINARY) 2>/dev/null || true
