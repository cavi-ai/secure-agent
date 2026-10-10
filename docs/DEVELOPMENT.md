# Development

[Documentation](README.md) · [Project home](../README.md)

This guide is for building and testing the repository. To run the packaged app, use [Getting started](GETTING_STARTED.md). See [Contributing](../CONTRIBUTING.md) for component standards and pull requests.

## Build and install

Prerequisites: macOS 14+, Go 1.26.9 or newer (as declared in `go.mod`), Python 3.10+, Node.js for console tests, and Xcode with the macOS 27.0 SDK and a Swift 6 toolchain. App packaging and local Swift builds/tests use `packaging/swift_macos.sh` to select `macosx27.0` for both compilation and linking; an unavailable SDK fails the build. Packaging also checks that both executable architectures record SDK 27.0 and minimum macOS 14.0.

```bash
git clone https://github.com/cavi-ai/secure-agent.git
cd secure-agent
make build      # Go binaries in bin/; Swift executable in menubar/.build/release/
make app        # build the app bundle required by the bundle layout check
make test       # full Go + Swift + Python + E2E suites
make install    # build "Secure Agent.app", install it to /Applications and launch it (no LaunchAgents)
```

`make install` replaces `/Applications/Secure Agent.app` (the previous copy goes to the Trash) and opens only that copy. The build output in `dist/` is never registered or opened: macOS binds the file-telemetry helper to the copy that registered it, so only the copy in `/Applications` registers, re-registers or repairs it. Any other copy shows "Secure Agent must run from /Applications to manage file telemetry".

`make build` includes the collector and the macOS menu bar. On Linux, use `make daemon cli collector`. Production Go binaries use `CGO_ENABLED=0`; the Go race detector in macOS CI uses cgo for instrumentation.

## Build an app or DMG

```bash
make icon       # one-time icon generation, or after changing artwork
make app        # assemble and sign dist/Secure Agent.app
make dmg        # build the app and package dist/SecureAgent-<version>.dmg
```

For local use, `make install` builds, installs and launches the `/Applications` copy. Building a DMG is a development task; end users can download one without the build toolchain.

### Signing and notarization

`make install`, `make app`, and `make dmg` all resolve `CODESIGN_IDENTITY` the same way (`packaging/lib/sign_identity.sh`): the first "Apple Development" identity in your keychain, else the first "Developer ID Application" identity, else ad-hoc (`-`) as the fallback. Signing with a real identity — Apple Development or Developer ID — is what lets the ES helper's Full Disk Access and Login Items grants survive rebuilds; the first build under a new identity still needs one Login Items approval and one Full Disk Access grant. An ad-hoc build loses both grants on every rebuild.

Override the identity explicitly, e.g. for proper Gatekeeper distribution:

```bash
export CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
xcrun notarytool store-credentials secure-agent-notary --apple-id you@example.com --team-id TEAMID
export NOTARY_PROFILE=secure-agent-notary
make dmg   # signs, notarizes, and staples both the app and the DMG
```

## Run validation

For documentation, run `make docs-check docs-test docs`. After changing CLI help, embedded defaults or API route metadata, run `make docs-reference` first and include the generated reference diff. See [Documentation artifacts](CONSUMER.md) for archive builds, release identity and the host contract.

`make lint` runs Go vet and formatting checks. `make test` runs the local aggregate suite. The commands below let you run each component directly; CI also checks Linux builds, Go races, dependency vulnerabilities, packaging helpers, personal paths and secret scanning. See the [workflow](../.github/workflows/ci.yml) for its exact commands.

The repository includes test suites across Go, Python, Swift, and end-to-end shell smoke testing.

```bash
# 1. Run Go daemon unit & integration tests
go test ./...

# 2. Run Python plugin hook test suites (including Cursor protocol)
python3 plugin/hooks/test_secret_guard.py
python3 plugin/hooks/test_injection_scan.py
python3 plugin/hooks/test_activity_log.py
python3 plugin/hooks/test_cursor_hooks.py

# 3. Run Swift menu bar package tests
bash packaging/swift_macos.sh test --package-path menubar
bash packaging/test/test_status_item_lifecycle.sh

# 4. Run console JS unit tests + DOM tests + asset lint
node --test 'packaging/test/console/*.test.mjs'
python3 -m unittest discover -s packaging/test/console_dom -p 'test_*.py'
python3 packaging/test/console_dom/run_dom_tests.py
./packaging/test/check_console_css.sh

# 5. Run end-to-end smoke test script
./packaging/test/e2e_smoke.sh

# 6. Check the built app bundle layout (after make app)
./packaging/test/check_bundle_layout.sh
```

The DOM runner uses an installed Chrome or Chromium binary with `--dump-dom`; set `CHROME_BIN` if it is not found automatically. Swift builds and tests require the selected macOS 27 SDK; an older SDK does not satisfy that gate. Bundle layout checks require a built app: run `make app` before `make test` or the standalone bundle check.

The source installer changes `/Applications` and launches the app. Unit tests and builds do not require installing over your running app. Use a temporary config/socket when running a test daemon rather than replacing your personal monitoring state.

## Repository layout

```text
secure-agent/
├── cmd/                  # CLI and reference fleet collector
├── daemon/
│   ├── cmd/              # secure-agentd entry point
│   └── internal/         # Collectors, bus, correlation, store, API, config
│       └── api/web_dist/ # Embedded console assets (canonical source)
├── plugin/
│   ├── hooks/            # Secret guard, injection scanner, activity log
│   └── install.sh       # Development hook symlink helper
├── menubar/
│   ├── Package.swift    # SwiftPM manifest
│   └── Sources/         # AppKit/SwiftUI interface and setup
├── packaging/
│   ├── make_app.sh      # Universal app build and signing
│   ├── make_dmg.sh      # DMG packaging and optional notarization
│   ├── make_icon.sh     # AppIcon.icns generation
│   ├── install.sh       # Build, install to /Applications, launch
│   ├── uninstall.sh     # Legacy installation cleanup
│   └── test/            # Go/live smoke, packaging and console checks
├── docs/                 # User guides and technical references
├── CONTRIBUTING.md
└── SECURITY.md
```

## Development hook symlinks

```bash
./plugin/install.sh
```

This links Python scripts from `plugin/hooks/` into `~/.claude/hooks/` and `~/.cursor/hooks/`. It does **not** register them in Claude's `settings.json` or Cursor's `hooks.json`; symlinks alone do not activate hook invocation. The packaged app's Setup installs and registers the selected harness's hooks while preserving existing user hooks. Keep the source checkout available while using development symlinks.
