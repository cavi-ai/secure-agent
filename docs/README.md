# Secure Agent documentation

[Documentation](README.md) · [Project home](../README.md)

New to Secure Agent? Start with [Getting started](GETTING_STARTED.md), then follow [Your first observed session](FIRST_SESSION.md). Learn how to interpret [coverage and evidence](CONCEPTS.md) before enabling additional protection. These guides describe the current `main` checkout. Published downloads may lag behind it; check the [release notes](https://github.com/cavi-ai/secure-agent/releases) for your installed version.

## Install and operate

| Guide | What you can do |
|---|---|
| [Getting started](GETTING_STARTED.md) | Install, set up one harness, check coverage, enable telemetry, update and troubleshoot |
| [Your first observed session](FIRST_SESSION.md) | Run a small task, identify its evidence and export a report |
| [Troubleshooting](TROUBLESHOOTING.md) | Diagnose unavailable daemons, permissions, hooks, routing, stale data and fleet authentication |
| [Console and CLI](USAGE.md) | Review findings, export sessions, inspect resource use, manage worktrees and cleanup |
| [File and egress protection](PROTECTION.md) | Configure guard modes, register fingerprints, route traffic and review enforcement limits |
| [Local chat and commands](SYSTEM_AGENT.md) | Set up Ollama chat, review recommendations and confirm commands or harness handoffs |
| [Fleet](FLEET.md) | Enroll nodes, provision a collector and read fleet status |

## Reference and development

| Reference | Contents |
|---|---|
| [Coverage and evidence](CONCEPTS.md) | Separate guard, activity and payload coverage; interpret states and scoped decisions |
| [Configuration](CONFIGURATION.md) | YAML overlays, reload behavior, firewall and resource policies, runtime overrides |
| [API](API.md) | Unix socket endpoints, peer roles, console authentication and collector contract |
| [Architecture](ARCHITECTURE.md) | Collectors, harness trace coverage, session identity, event flow, storage and native UI |
| [Development](DEVELOPMENT.md) | Toolchain requirements, build/install commands, signing, tests and repository layout |
| [Contributing](../CONTRIBUTING.md) | Component standards and submitting changes |
| [CLI commands](reference/CLI.md) | Generated help from the current CLI |
| [Default configuration](reference/DEFAULTS.md) | Generated embedded YAML defaults |
| [API route registry](reference/ROUTES.md) | Generated routes and access classifications |
| [Documentation artifacts](CONSUMER.md) | Navigation, build/check commands, version identity and host ingestion contract |

## Security boundaries

| Document | Scope |
|---|---|
| [Guard threat model](GUARD_THREAT_MODEL.md) | Hook enforcement, bypass classes and failure behavior |
| [Firewall threat model](FIREWALL_THREAT_MODEL.md) | Payload inspection, secret handling, uninspected traffic and request limits |
| [Advisor threat model](ADVISOR_THREAT_MODEL.md) | Local-only model calls, evidence tools and advisory limits |
| [Security policy](../SECURITY.md) | Reporting vulnerabilities and privacy policy |

## Keep documentation in sync

When behavior changes, update its user guide and its reference together. Keep installation steps in Getting started, configuration fields in Configuration, endpoint contracts in API, and release history in [CHANGELOG](../CHANGELOG.md). The README should link to those guides instead of duplicating them.

Run `make docs-reference` when CLI help, defaults or route metadata changes, then `make docs-check docs-test docs`. CI checks generated drift, examples, links, navigation and artifact integrity. See [Documentation artifacts](CONSUMER.md) for release builds and the hosting contract.
