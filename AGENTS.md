# Agent Guidelines for secure-agent

## Execution and Approval Rules

1. **Pre-approved Development & Testing Commands**:
   - Building Go binaries (`go build`), running test suites (`go test ./...`), executing Python hook tests (`python3 -m pytest` or `python3 test_*.py`), and running local shell smoke scripts (`packaging/test/e2e_smoke.sh`) are **pre-approved**.
   - Do not prompt the user for permission when executing commands in the workspace terminal for building, testing, linting, or debugging `secure-agent`.

2. **Data & Security Safety Rules**:
   - Never write secret values (passwords, tokens, private keys) to logs, code, or committed files.
   - All sensitive data must use redacting placeholders (`[REDACTED]`).
   - Implementation plans and scratch specs stay local; only the published docs (README, CHANGELOG, `docs/*.md`) are committed.

3. **Go Systems Programming Standards**:
   - Keep the core daemon pure Go (`cgo` disabled) to ensure portability across macOS architectures and future Linux builds.
   - Maintain non-blocking channel pub/sub and best-effort storage writes so low-level system monitoring is resilient to storage delays.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes_tool` or `query_graph_tool` instead of Grep
- **Understanding impact**: `get_impact_radius_tool` instead of manually tracing imports
- **Code review**: `detect_changes_tool` + `get_review_context_tool` instead of reading entire files
- **Finding relationships**: `query_graph_tool` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview_tool` + `list_communities_tool`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
| ------ | ---------- |
| `detect_changes_tool` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context_tool` | Need source snippets for review — token-efficient |
| `get_impact_radius_tool` | Understanding blast radius of a change |
| `get_affected_flows_tool` | Finding which execution paths are impacted |
| `query_graph_tool` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes_tool` | Finding functions/classes by name or keyword |
| `get_architecture_overview_tool` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes_tool` for code review.
3. Use `get_affected_flows_tool` to understand impact.
4. Use `query_graph_tool` pattern="tests_for" to check coverage.
