# secure-agent

A lightweight, always-on AI-agent security monitor for macOS.

`secure-agent` observes AI-agent process trees (Claude Code, Cursor, Codex, etc.), monitors file access and network connections, and correlates sensitive file reads followed by foreign network egress. It also includes plugin hooks for in-harness mutation gating and policy enforcement.

## Components

- `daemon/`: Go daemon (`secure-agentd`) running `eslogger`, `libproc` socket sampler, agent tagger, transcript scanner, sliding-window correlator, and Unix domain socket control API.
- `plugin/`: Harness plugin (Claude Code / Cursor) for PreToolUse mutation blocking and PostToolUse prompt injection scanning.
- `packaging/`: launchd plist and installation/smoke scripts.

## License

MIT
