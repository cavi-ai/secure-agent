# Contributing to secure-agent

Thank you for your interest in contributing to `secure-agent`! We welcome bug reports, feature requests, documentation improvements, and code contributions from the open-source community.

This document provides guidelines and workflows for contributing to `secure-agent`.

---

## 📋 Code of Conduct & Core Principles

- **Developer Velocity + Security**: Monitoring must be fast, resilient, and non-intrusive. Telemetry collection should never block agent execution or introduce significant CPU/memory overhead.
- **Pure Go Daemon**: The core daemon (`daemon/`) must remain pure Go (`CGO_ENABLED=0`) to ensure cross-architecture portability and ease of compilation.
- **Fail-Safe Gating**: Plugin hooks must execute defensively within tight latency budgets (<100ms) and handle malformed JSON payloads gracefully without crashing harness sessions.
- **Redaction & Privacy**: Never commit private credentials, tokens, or live Keychain data. All test fixtures must use `[REDACTED]` placeholders or dummy mock data.

---

## 🛠️ Prerequisites & Local Setup

Ensure you have the following installed on your macOS development environment:

- **Go**: 1.22 or newer
- **Swift**: 6.0 / Xcode Command Line Tools (macOS 14+)
- **Python**: 3.10 or newer

### Setup Workflow

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/secure-agent.git
   cd secure-agent
   ```

2. **Verify existing test suites**:
   ```bash
   go test ./...
   python3 plugin/hooks/test_secret_guard.py
   python3 plugin/hooks/test_injection_scan.py
   python3 plugin/hooks/test_activity_log.py
   swift test --package-path menubar
   ./packaging/test/e2e_smoke.sh
   ```

---

## 🧩 Component Standards

### 1. Go Telemetry Daemon (`daemon/`)

- Located in `daemon/cmd/secure-agentd` and `daemon/internal/`.
- **Pure Go**: Do not introduce `cgo` dependencies.
- **Non-blocking Pub/Sub**: The central event bus (`daemon/internal/bus`) uses non-blocking channel dispatch so slow consumers or storage writes do not back-pressure low-level monitoring.
- **Storage Safety**: Database writes (`SQLite` and `JSONL`) are best-effort; database errors must degrade gracefully to log warnings without terminating event collection.

### 2. Python Plugin Hooks (`plugin/hooks/`)

- Located in `plugin/hooks/`.
- **Dual Protocol Support**: Hooks must emit compatible responses for both Claude Code (`decision: "block"`, `reason: "..."`) and Cursor (`permission: "deny"`, `user_message: "..."`).
- **Latency Budget**: Hooks run on every tool call. Maintain sub-50ms execution times.
- **Test Coverage**: Any new regex pattern or rule in `secret_guard.py` or `injection_scan.py` must include corresponding `ALLOW` and `DENY` test cases in `test_secret_guard.py` / `test_injection_scan.py`.

### 3. Swift Menu Bar (`menubar/`)

- Located in `menubar/`.
- **Decoupled Architecture**: The Swift app is a pure view layer that polls the daemon's Unix domain socket API (`/status`, `/flags`, `/events`). It contains no threat detection logic.
- **Graceful Offline Mode**: If the daemon socket is absent or restarting, the menu bar app must cleanly transition to a "Daemon Offline" status without crashing.

---

## 🧪 Testing Your Changes

Before submitting a Pull Request, verify that all test suites pass cleanly:

```bash
# 1. Run Go unit & integration tests
go test -v ./...

# 2. Run Python plugin hook tests
python3 plugin/hooks/test_secret_guard.py
python3 plugin/hooks/test_injection_scan.py
python3 plugin/hooks/test_activity_log.py

# 3. Run Swift menu bar package tests
swift test --package-path menubar

# 4. Run end-to-end smoke test
./packaging/test/e2e_smoke.sh
```

---

## 📥 Submitting a Pull Request

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. Commit your changes following conventional commit syntax (`feat: ...`, `fix: ...`, `docs: ...`, `chore: ...`).
3. Ensure all test suites pass locally.
4. Push your branch and open a Pull Request against `main`.

Thank you for helping secure the future of autonomous AI code agents!
