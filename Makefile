.PHONY: all build test install uninstall clean daemon menubar cli smoke app dmg icon

app:
	./packaging/make_app.sh

dmg:
	./packaging/make_dmg.sh

icon:
	./packaging/make_icon.sh


# Binaries
BIN_DIR := $(HOME)/.local/bin
DAEMON_BIN := $(BIN_DIR)/secure-agentd
CLI_BIN := $(BIN_DIR)/secure-agent
MENUBAR_BIN := $(BIN_DIR)/secure-agent-menubar

all: build

build: daemon cli menubar

lint:
	@echo "==> go vet ./..."
	go vet ./...
	@echo "==> gofmt check..."
	@test -z "$$(gofmt -l daemon cmd)" || { echo "gofmt needed:"; gofmt -l daemon cmd; exit 1; }

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

daemon:
	@echo "==> Building secure-agentd daemon..."
	go build -ldflags "-X github.com/cavi-ai/secure-agent/daemon/internal/api.Version=$(VERSION)" -o bin/secure-agentd ./daemon/cmd/secure-agentd

cli:
	@echo "==> Building secure-agent CLI..."
	go build -o bin/secure-agent ./cmd/secure-agent

menubar:
	@echo "==> Building secure-agent-menubar..."
	cd menubar && swift build -c release

test:
	@echo "==> Running Go unit tests..."
	go test ./...
	@echo "==> Running Swift package tests..."
	swift test --package-path menubar
	@echo "==> Running Python hook tests..."
	python3 plugin/hooks/test_secret_guard.py
	python3 plugin/hooks/test_injection_scan.py
	python3 plugin/hooks/test_activity_log.py
	@echo "==> Running E2E smoke test scenario..."
	./packaging/test/e2e_smoke.sh

smoke:
	./packaging/test/e2e_smoke.sh

install:
	@echo "==> Installing secure-agent..."
	./packaging/install.sh

uninstall:
	@echo "==> Uninstalling secure-agent..."
	./packaging/uninstall.sh

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf bin/
	rm -rf menubar/.build/
	rm -f *.db *.db-journal *.jsonl
