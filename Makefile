.PHONY: all build test test-menubar-rendering test-setup-session-live test-guard-workflow-live install uninstall clean daemon menubar cli collector smoke app dmg release icon lint docs docs-reference docs-check docs-test docs-archive

docs-reference:
	python3 packaging/docs/build.py reference

docs-check:
	python3 packaging/docs/build.py check

docs-test:
	python3 -m unittest discover -s packaging/docs -p 'test_*.py'

docs:
	python3 packaging/docs/build.py build

docs-archive:
	python3 packaging/docs/build.py archive

app:
	./packaging/make_app.sh

dmg:
	./packaging/make_dmg.sh

# Signed release build: Developer ID Application cert + notarization.
# Usage: make release [VERSION=x.y.z]
# Env: explicit CODESIGN_IDENTITY (Developer ID Application) and
#      NOTARY_PROFILE (keychain profile for notarytool), or DEVELOPER_TEAM
#      (team ID: Developer ID signing through an Xcode export, notarized with
#      the signed-in Xcode account).
release: VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
release:
	RELEASE_BUILD=1 VERSION="$(VERSION)" CODESIGN_IDENTITY="$(CODESIGN_IDENTITY)" NOTARY_PROFILE="$(NOTARY_PROFILE)" DEVELOPER_TEAM="$(DEVELOPER_TEAM)" ./packaging/make_dmg.sh

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
	bash packaging/swift_macos.sh build --package-path menubar -c release

# Interactive macOS check; requires Screen Recording and Full Disk Access.
test-menubar-rendering:
	python3 packaging/check_menu_bar.py
	bash packaging/test/test_status_item_rendering.sh

# Opt-in: graphical macOS login and authenticated Codex; no installed app changes.
test-setup-session-live:
	python3 packaging/test/setup_session_live.py

test-guard-workflow-live:
	python3 packaging/test/guard_workflow_live.py

test:
	@echo "==> Running Go unit tests..."
	go test ./... -count=1
	@echo "==> Running Swift package tests..."
	bash packaging/swift_macos.sh test --package-path menubar
	bash packaging/test/test_status_item_lifecycle.sh
	python3 packaging/test/test_menu_bar_tracking.py
	@echo "==> Running Python hook tests..."
	python3 plugin/hooks/test_secret_guard.py
	python3 plugin/hooks/test_shell_review.py
	python3 -m unittest discover -s packaging/classifier -p 'test_*.py'
	python3 plugin/hooks/test_injection_scan.py
	python3 plugin/hooks/test_activity_log.py
	python3 plugin/hooks/test_cursor_hooks.py
	python3 packaging/test/test_release_packaging.py
	python3 packaging/test/test_setup_session_live.py
	$(MAKE) test-guard-workflow-live
	@echo "==> Checking console assets..."
	./packaging/test/check_console_css.sh
	@echo "==> Checking app bundle layout..."
	./packaging/test/check_bundle_layout.sh
	bash packaging/test/test_devid_export.sh
	@echo "==> Running console JS unit tests..."
	node --test 'packaging/test/console/*.test.mjs'
	@echo "==> Running console DOM tests..."
	python3 -m unittest discover -s packaging/test/console_dom -p 'test_*.py'
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
