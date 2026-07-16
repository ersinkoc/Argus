BINARY   := todo-server
DB       := todos.db
PORT     ?= 8080
GO       := go

.PHONY: all run test build clean

all: build

run: build
	PORT=$(PORT) TODO_DB_PATH=$(DB) ./$(BINARY)

test:
	$(GO) test -v -count=1 ./...

build:
	$(GO) build -o $(BINARY) .

clean:
	$(RM) $(BINARY) $(DB)
