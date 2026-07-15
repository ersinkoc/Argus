VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)
BINARY := argus

.PHONY: all build test test-compile test-short test-full test-verbose test-timing test-race test-e2e test-stress clean lint fmt-check dep-guard run bench cover coverage-ci validate

all: lint test-full test-race build

build: admin-ui
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/argus/
	@echo "Built $(BINARY) $(VERSION)"

admin-ui:
	@echo "Building admin UI..."
	cd admin-ui && npm ci --silent 2>/dev/null || npm install --silent && npx vite build --logLevel error
	@echo "Copying admin UI to embed directory..."
	cp -r admin-ui/dist/. internal/admin/adminui/
	@echo "Admin UI built and embedded."

test: test-full

test-compile:
	go test ./... -run '^$$' -count=1

test-short:
	go test ./... -short -count=1 -timeout 60s

test-full:
	go test ./... -count=1 -timeout 60s

test-timing:
	bash scripts/test-package-timing.sh

test-verbose:
	go test ./... -count=1 -timeout 60s -v

# Race is kept as a separate lane from the default suite.
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

fmt-check:
	bash scripts/gofmt-check.sh

dep-guard:
	bash scripts/check-internal-deps.sh

coverage-ci:
	go test ./... -count=1 -timeout 60s -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tee coverage-summary.txt
	@grep "^total:" coverage-summary.txt

validate: build
	./$(BINARY) -config configs/argus.json -validate

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-* coverage.out coverage.html

run: build
	./$(BINARY) -config configs/argus.json

run-dev: build
	./$(BINARY) -config configs/argus-dev.json

dev: admin-ui
	@echo "Starting dev environment (backend:9090 + frontend:5173)..."
	@bash dev.sh

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

test-e2e: e2e

test-stress: e2e-stress

e2e: docker-up
	@echo "Running E2E basic tests..."
	bash scripts/test-e2e-full.sh

e2e-advanced: docker-up
	@echo "Running advanced E2E tests..."
	bash scripts/test-e2e-advanced.sh

e2e-stress: docker-up
	@echo "Running stress & security tests..."
	bash scripts/test-e2e-stress.sh

e2e-all: docker-up
	@echo "Running all E2E tests..."
	bash scripts/test-e2e-full.sh
	bash scripts/test-e2e-advanced.sh
	bash scripts/test-e2e-stress.sh

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
