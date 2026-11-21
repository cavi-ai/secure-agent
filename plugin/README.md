# Secure Agent hooks

The Secure Agent app installs and manages hooks for Claude Code, Cursor, Codex, OpenClaw, Antigravity, Hermes, and OpenCode v2. See [Getting started](https://github.com/cavi-ai/secure-agent/blob/main/docs/GETTING_STARTED.md) for setup and coverage. Python hooks require Python 3.12 or later on your PATH.

## Claude Code marketplace

Claude Code users can also install the Secure Agent hooks through the CAVI marketplace:

```sh
claude plugin marketplace add cavi-ai/plugins
claude plugin install secure-agent@cavi-ai --scope user
```

Use one Secure Agent hook integration for Claude Code. This plugin supplies the hooks; separate manual hook registration is unnecessary. Check session coverage in Secure Agent after setup.
