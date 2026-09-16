.PHONY: all build test install uninstall clean daemon menubar cli collector smoke app dmg icon lint

app:
	./packaging/make_app.sh

dmg:
	./packaging/make_dmg.sh

# Signed release build: Developer ID Application cert + notarization.
# Usage: make release [VERSION=x.y.z]
# Env: CODESIGN_IDENTITY (default: Apple Development for stable TCC grants)
#      NOTARY_PROFILE (keychain profile for notarytool — required for
#      distribution beyond this machine)
release: VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
release: CODESIGN_IDENTITY ?= $(shell security find-identity -v -p codesigning 2>/dev/null | grep -oE '"[^"]*Apple Development[^"]*"' | head -1 | tr -d '"')
release:
	VERSION=$(VERSION) CODESIGN_IDENTITY="$(CODESIGN_IDENTITY)" NOTARY_PROFILE="$(NOTARY_PROFILE)" ./packaging/make_dmg.sh

icon:
	./packaging/make_icon.sh


# Binaries
BIN_DIR := $(HOME)/.local/bin
DAEMON_BIN := $(BIN_DIR)/secure-agentd
CLI_BIN := $(BIN_DIR)/secure-agent
MENUBAR_BIN := $(BIN_DIR)/secure-agent-menubar

all: build

build: daemon cli menubar collector

lint:
	@echo "==> go vet ./..."
	go vet ./...
	@echo "==> gofmt check..."
	@test -z "$$(gofmt -l daemon cmd)" || { echo "gofmt needed:"; gofmt -l daemon cmd; exit 1; }

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

daemon:
	@echo "==> Building secure-agentd daemon..."
	CGO_ENABLED=0 go build -ldflags "-X github.com/cavi-ai/secure-agent/daemon/internal/api.Version=$(VERSION)" -o bin/secure-agentd ./daemon/cmd/secure-agentd

cli:
	@echo "==> Building secure-agent CLI..."
	CGO_ENABLED=0 go build -o bin/secure-agent ./cmd/secure-agent

collector:
	@echo "==> Building secure-agent-collector..."
	CGO_ENABLED=0 go build -o bin/secure-agent-collector ./cmd/secure-agent-collector

menubar:
	@echo "==> Building secure-agent-menubar..."
	cd menubar && swift build -c release

test:
	@echo "==> Running Go unit tests..."
	go test ./... -count=1
	@echo "==> Running Swift package tests..."
	swift test --package-path menubar
	@echo "==> Running Python hook tests..."
	python3 plugin/hooks/test_secret_guard.py
	python3 plugin/hooks/test_injection_scan.py
	python3 plugin/hooks/test_activity_log.py
	@echo "==> Checking console assets..."
	./packaging/test/check_console_css.sh
	@echo "==> Running console JS unit tests..."
	node --test 'packaging/test/console/*.test.mjs'
	@echo "==> Running console DOM tests..."
	python3 packaging/test/console_dom/run_dom_tests.py
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
	rm -f events.db events.db-journal events.db-wal events.db-shm events.jsonl
