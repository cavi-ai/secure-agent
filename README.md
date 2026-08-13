# secure-agent

[![Go Reference](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Swift](https://img.shields.io/badge/Swift-6.0-FA7343?style=flat&logo=swift)](https://swift.org/)
[![macOS](https://img.shields.io/badge/macOS-14.0+-000000?style=flat&logo=apple)](https://apple.com/macos)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**`secure-agent`** is a lightweight, always-on AI-agent security monitor and harness guard designed for macOS.

As AI coding agents (Claude Code, Cursor, Codex, OpenClaw, Copilot, etc.) gain increasing autonomy in local development environments, they gain execution privileges to read local sensitive files, mutate shell configurations, access credential stores, and initiate external network connections. `secure-agent` provides a non-intrusive, multi-layered defense system that enforces zero-trust boundaries around AI agent process trees without disrupting developer velocity.

---

## 🌟 Key Features

- 🛡️ **In-Harness Secret Guard (`PreToolUse` Gating)**  
  Synchronously intercepts agent tool calls to block unauthorized reads or mutations targeting Keychain files (`login.keychain-db`), shell configurations (`.zshrc`, `.zshenv`, `/etc/paths`), SSH keys, and cloud credentials. Supports Claude Code and Cursor hook protocols.

- 💉 **Prompt Injection Detection (`PostToolUse` Scanning)**  
  Scans tool output streams, web fetches, and agent transcripts in real time for indirect prompt injection vectors and credential leakage.

- ⚡ **Low-Overhead System Telemetry Daemon (`secure-agentd`)**  
  A pure Go daemon that consumes macOS Endpoint Security events (`eslogger`) and periodically samples per-process active network sockets (`libproc`). Maintains a lightweight footprint (<30 MB RAM, <2% CPU).

- 🔗 **Sliding-Window Event Correlation Engine**  
  Correlates process file activity with network egress. Automatically raises security flags when an agent process reads a sensitive file (e.g. `~/.aws/credentials` or `.env`) followed by an outbound socket connection to a domain outside its pre-approved vendor allowlist.

- 🚨 **Rotation Intel & Incident Containment**  
  Analyzes compromised secret exposures, categorizes risk severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), assesses blast radius, and generates ordered step-by-step remediation checklists with copy-paste shell commands via `/incidents` and a native Swift UI remediation modal.

- 🌐 **Opt-In Local MITM Proxy & Payload Inspection (`127.0.0.1:8443`)**  
  Features an inline HTTP/HTTPS proxy server with dynamic TLS certificate generation (`CAManager`) that inspects request streams for outbound credential leaks (`redact.Detect`) and response streams for prompt injection attacks (`injection.Detect`).

- 🔌 **Local Control & Query API**  
  Exposes a secure HTTP API over a Unix domain socket (`~/.config/secure-agent/daemon.sock`) for querying status, events, flags, incidents, and initiating process termination.

- ⚙️ **Extensible YAML Rules & Allowlists**  
  Easily customize sensitive path patterns, agent binary matchers, vendor network allowlists (`anthropic.com`, `cursor.sh`, `openai.com`), and proxy settings.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Harness ["AI Agent Harness (Claude Code / Cursor)"]
        H1["PreToolUse Hook\n(Secret Guard)"] --> H2["Tool Execution"]
        H2 --> H3["PostToolUse Hook\n(Injection Scanner)"]
        H1 -->|JSONL Audit| LOG["~/.local/state/secure-agent/activity.jsonl"]
    end

    subgraph OS Telemetry ["macOS Subsystems"]
        ES["eslogger\n(open, exec, rename, unlink, tcc_modify)"]
        LP["libproc\n(Socket Sampler)"]
    end

    subgraph Daemon ["secure-agentd (Go Daemon)"]
        C1["File Watch Collector"]
        C2["Net Socket Sampler"]
        C3["Process Tagger"]
        C4["Transcript & Log Scanner"]

        ES --> C1
        LP --> C2
        LOG --> C4

        C1 --> BUS["Event Bus\n(Non-blocking Pub/Sub)"]
        C2 --> BUS
        C3 --> BUS
        C4 --> BUS

        BUS --> CORR["Sliding-Window\nCorrelation Engine"]
        CORR --> STORE["Store Engine\n(SQLite + JSONL)"]
        STORE --> API["Unix Socket API\n(~/.config/secure-agent/daemon.sock)"]
    end

    subgraph UI ["User Interface"]
        API --> MENUBAR["Swift Menu Bar App\n(Status, Flags & Kill Switch)"]
        API --> CLI["curl / CLI Tools"]
    end
```

---

## 🚀 Quick Start

### Prerequisites

- **macOS**: 14.0 (Sonoma) or newer
- **Go**: 1.22 or newer
- **Swift**: 6.0 / Xcode Command Line Tools
- **Python**: 3.10 or newer

### Automated Installation

Run the provided installation script to build binaries, install LaunchAgents, and set up plugin hooks:

```bash
git clone https://github.com/cavi-ai/secure-agent.git
cd secure-agent
./packaging/install.sh
```

> **Note**: To enable full Endpoint Security telemetry via `eslogger`, grant Full Disk Access to `~/.local/bin/secure-agentd` under **System Settings → Privacy & Security → Full Disk Access**.

### Plugin Hook Installation

To link the Python hook scripts into Claude Code and Cursor harness directories manually:

```bash
./plugin/install.sh
```

This creates symbolic links from `plugin/hooks/` to:
- `~/.claude/hooks/`
- `~/.cursor/hooks/`

---

## ⚙️ Configuration

`secure-agent` loads default configuration rules and applies user overlays from `~/.config/secure-agent/config.yaml`.

```yaml
# Sensitive file path patterns to monitor
sensitive_globs:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/id_*"
  - "~/.aws/credentials"
  - "~/.config/gh/hosts.yml"

sensitive_paths:
  - "~/.aws"
  - "~/.ssh"

keychain_markers:
  - "library/keychains"
  - ".keychain-db"
  - "login.keychain"

# Agent binary matching rules
agents:
  - name: claude
    match: ["claude"]
  - name: cursor
    match: ["Cursor Helper", "cursor"]
  - name: codex
    match: ["codex"]

# Pre-approved egress domains per agent
vendor_allowlist:
  claude: ["anthropic.com", "claude.ai"]
  cursor: ["cursor.sh", "cursor.com"]
  codex: ["openai.com", "api.openai.com"]

# Network sampling frequency
net_sample_interval_ms: 2000

# Socket & storage locations
socket_path: "~/.config/secure-agent/daemon.sock"
db_path: "~/.local/state/secure-agent/events.db"
jsonl_path: "~/.local/state/secure-agent/events.jsonl"

# Opt-in local proxy configuration
proxy_enabled: true
proxy_port: 8443
proxy_ca_cert_path: "~/.config/secure-agent/ca.crt"
proxy_ca_key_path: "~/.config/secure-agent/ca.key"
```

---

## 🔌 Unix Socket Control API

The Go daemon listens on a local Unix domain socket (`~/.config/secure-agent/daemon.sock`).

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/status` | `GET` | Returns daemon running state, uptime, active agent count, and proxy status. |
| `/flags` | `GET` | Returns recent security correlation flags (accepts optional `?limit=N`). |
| `/events` | `GET` | Returns recent raw system events (accepts optional `?limit=N`). |
| `/incidents` | `GET` | Returns rotation intel postmortem reports & checklists (`?id=ID`, `?format=markdown`). |
| `/kill` | `POST` | Terminate an agent process tree by PID (`{"pid": 12345}`). |

### Example Query

```bash
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/status
```

```json
{
  "running": true,
  "uptime": "2h45m12s",
  "active_agents": 2
}
```

```bash
curl --unix-socket ~/.config/secure-agent/daemon.sock http://unix/flags?limit=10
```

---

## 🧪 Testing & Verification

The repository includes test suites across Go, Python, Swift, and end-to-end shell smoke testing.

```bash
# 1. Run Go daemon unit & integration tests
go test ./...

# 2. Run Python plugin hook test suites
python3 plugin/hooks/test_secret_guard.py
python3 plugin/hooks/test_injection_scan.py
python3 plugin/hooks/test_activity_log.py

# 3. Run Swift menu bar package tests
swift test --package-path menubar

# 4. Run end-to-end smoke test script
./packaging/test/e2e_smoke.sh
```

---

## 📂 Repository Layout

```
secure-agent/
├── daemon/               # Go telemetry daemon (secure-agentd)
│   ├── cmd/              # Main executable entrypoint
│   └── internal/         # Collectors, bus, correlator, store, API, config
├── plugin/               # Harness plugin hooks (Claude Code / Cursor)
│   ├── hooks/            # secret_guard.py, injection_scan.py, activity_log.py
│   └── install.sh        # Symlink installer script
├── menubar/              # Native Swift menu bar app (secure-agent-menubar)
│   ├── Package.swift     # SwiftPM manifest
│   └── Sources/          # AppKit / SwiftUI NSStatusItem interface
├── packaging/            # System deployment scripts and launchd plists
│   ├── install.sh        # Build & LaunchAgent installer
│   └── test/             # E2E smoke testing harness
├── CONTRIBUTING.md       # Open-source contribution guidelines
└── SECURITY.md           # Security disclosure policy
```

---

## 🤝 Contributing

We welcome community contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide for details on development workflows, coding standards, and submitting pull requests.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
