# Agent Guidelines for secure-agent

## Execution and Approval Rules

1. **Pre-approved Development & Testing Commands**:
   - Building Go binaries (`go build`), running test suites (`go test ./...`), executing Python hook tests (`python3 -m pytest` or `python3 test_*.py`), and running local shell smoke scripts (`packaging/test/e2e_smoke.sh`) are **pre-approved**.
   - Do not prompt the user for permission when executing commands in the workspace terminal for building, testing, linting, or debugging `secure-agent`.

2. **Data & Security Safety Rules**:
   - Never write secret values (passwords, tokens, private keys) to logs, code, or committed files.
   - All sensitive data must use redacting placeholders (`[REDACTED]`).
   - `docs/` specs and implementation plans are local artifacts and must never be committed to git.

3. **Go Systems Programming Standards**:
   - Keep the core daemon pure Go (`cgo` disabled) to ensure portability across macOS architectures and future Linux builds.
   - Maintain non-blocking channel pub/sub and best-effort storage writes so low-level system monitoring is resilient to storage delays.
