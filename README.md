# secure-agent

[![CI](https://github.com/cavi-ai/secure-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/cavi-ai/secure-agent/actions/workflows/ci.yml)
[![macOS](https://img.shields.io/badge/macOS-14.0+-000000?style=flat&logo=apple)](https://apple.com/macos)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**See what your local AI agents do, review security findings, and control sensitive file access and outbound secret exposure.**

Secure Agent combines a native macOS menu bar app, a local web console, a Go daemon and harness hooks. It tracks agent sessions, process families, model-call costs, file activity and network destinations. Optional guards can stop supported tool calls; an opt-in proxy inspects routed payloads for secret leaks.

<p align="center">
  <img src="assets/screenshots/console.png" alt="Secure Agent security console" width="920">
</p>

## Get started

1. Download `SecureAgent-<version>.dmg` from the [latest release](https://github.com/cavi-ai/secure-agent/releases/latest).
2. Drag **Secure Agent.app** to **Applications** and launch it. Requires **macOS 14+**.
3. Choose your harness in Setup. Install Claude Code or Cursor hooks, or continue with the selected harness's observation path.
4. Start an agent session and check its observed coverage. Enable file telemetry, guard prompts, traffic routing and local analysis separately as needed.

Follow [Getting started](docs/GETTING_STARTED.md), then [Your first observed session](docs/FIRST_SESSION.md) to see evidence and export a report. For problems, use [Troubleshooting](docs/TROUBLESHOOTING.md). To build from source, use [Development](docs/DEVELOPMENT.md).

These docs describe the current `main` checkout. The published release may have an earlier setup flow or fewer features; consult its [release notes](https://github.com/cavi-ai/secure-agent/releases).

## What you can do

| Goal | Guide |
|---|---|
| Review findings and incidents, tune alerts, inspect session history | [Console and CLI](docs/USAGE.md) |
| Gate sensitive file access, register secrets, inspect routed payloads | [File and egress protection](docs/PROTECTION.md) |
| Inspect session memory/CPU and configure resource budgets | [Resources](docs/USAGE.md#manage-session-resources) |
| Find worktrees, review cleanup and track reclaimed disk space | [Worktrees and cleanup](docs/USAGE.md#manage-worktrees-and-disk-space) |
| Chat with local Ollama and confirm proposed commands | [Local chat and commands](docs/SYSTEM_AGENT.md) |
| Collect signed events and posture from several nodes | [Fleet](docs/FLEET.md) |

## Understand the coverage

File guarding, system observation and payload inspection are separate capabilities. Claude Code and Cursor have supported guard hooks; other harnesses have varying process and transcript coverage. See the [harness coverage table](docs/ARCHITECTURE.md#collectors).

Named guard rules and the firewall default to monitoring. Some hook safety checks always deny credential-printing and guard/harness mutations. Guard prompts, firewall blocking and automatic resource interventions require separate configuration. Unrouted or tunneled traffic is not payload-inspected, and a manual hook check does not prove a live session invokes it. Read the [protection guide and limits](docs/PROTECTION.md) before relying on enforcement.

macOS is the primary platform for the app, Endpoint Security telemetry and DMG distribution. The daemon, CLI and collector also build on Linux with `CGO_ENABLED=0`, using `/proc` for process/network sampling. See [Linux and headless setup](docs/GETTING_STARTED.md#linux-and-headless-nodes).

## Documentation and contributing

The [documentation index](docs/README.md) links every guide and reference, including [Configuration](docs/CONFIGURATION.md), [API](docs/API.md), [Architecture](docs/ARCHITECTURE.md) and the threat models.

For development and pull requests, read [Contributing](CONTRIBUTING.md). Report vulnerabilities through the [security policy](SECURITY.md).

Distributed under the [MIT License](LICENSE).
