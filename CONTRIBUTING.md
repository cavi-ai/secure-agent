# Contributing to secure-agent

Bug reports, documentation improvements and code contributions are welcome. Start with [Development](docs/DEVELOPMENT.md) for toolchain requirements, builds, signing, tests and the repository layout. For product setup, use [Getting started](docs/GETTING_STARTED.md).

## Local setup

Fork the repository and clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/secure-agent.git
cd secure-agent
git checkout -b feat/my-change
```

Use the Go version declared in `go.mod` (currently 1.26.9). macOS app builds and Swift tests require Swift 6 and the macOS 27.0 SDK, selected by `packaging/swift_macos.sh`; deployment targets macOS 14+. Python 3.10+ runs the hooks; Node.js and Chrome/Chromium run the console tests. Follow the [development validation commands](docs/DEVELOPMENT.md#run-validation), including `make app` before the aggregate `make test` bundle check.

## Component standards

### Go daemon

- Keep production binaries pure Go (`CGO_ENABLED=0`).
- Keep event-bus publication non-blocking. Slow subscribers and storage must not stall low-level collection.
- Keep telemetry storage writes best-effort, with explicit evidence-health reporting when records are dropped or reads/writes fail. Do not return an empty successful result for unavailable evidence.
- Preserve authoritative persistence before applying process controls or changing protection. Telemetry's best-effort path does not authorize best-effort approval state.
- Preserve session and process-start identity when joining evidence or applying an action.

### Python harness hooks

- Keep Claude Code and Cursor response protocols compatible (`decision: "block"` / `reason` and `permission: "deny"` / `user_message`).
- Keep ordinary hook work lightweight. Interactive prompts deliberately wait for a decision up to their deadline; do not treat that path as a sub-100 ms operation.
- Handle malformed payloads and daemon failures according to the [guard failure posture](docs/GUARD_THREAT_MODEL.md#failure-posture).
- Add focused allow/deny regression cases for changed rules and patterns. Preserve hard denials protecting credential material and the guard's enforcement plane.

### Native app and web console

- Keep threat detection in the daemon. The Swift app presents state, manages setup and invokes supported controls.
- Consume SSE updates with the existing polling fallback. Preserve last-known data with a stale warning when an endpoint fails; clear the warning only after that source refreshes successfully.
- Keep user approvals scoped to the captured evidence and process family. Missing records and incomplete outcomes must remain explicit.
- Edit embedded console assets in `daemon/internal/api/web_dist/`, their canonical source.

### Privacy and documentation

- Never commit credentials, tokens, private keys or private machine paths. Use `[REDACTED]` or synthetic fixtures.
- Keep private plans, specs, discussions, scratch notes and generated evidence out of commits.
- Update the relevant user guide and reference when behavior changes. Use the [documentation index](docs/README.md) to find the owning page.
- Regenerate CLI/configuration/API inventories with `make docs-reference`, then run `make docs-check docs-test docs`. Keep every published page in `docs/navigation.json`.
- Keep version history in [CHANGELOG.md](CHANGELOG.md); do not turn the README into release notes.

## Submit a pull request

1. Keep the change focused and include regression coverage for changed behavior.
2. Run the relevant component checks and required repository gates. Report failed, unavailable or pending checks accurately.
3. Use conventional commit titles such as `feat:`, `fix:`, `docs:` or `chore:` and preserve repository signing requirements.
4. Inspect the diff for private artifacts and accidental sensitive data, then push the branch and open a pull request against `main` using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

Report vulnerabilities privately through [SECURITY.md](SECURITY.md).
