---
title: Claude Code — sign-in, settings and local models
summary: Sign Claude Code in or out, keep its API key in the keychain, edit its settings and hooks safely, and run it against local Ollama.
keywords: claude, claude code, anthropic, claude auth, setup-token, oauth token, anthropic_api_key, apikeyhelper, settings.json, hooks, claude.md, anthropic_base_url
---
Rules
- claude auth login opens a browser: terminal work for the operator.
- A token or API key is never written into a repository, a CLAUDE.md or a settings file committed to git.
- secure-agent's hooks live in ~/.claude/hooks and are wired in ~/.claude/settings.json under "hooks": keep them.

Sign-in
- claude auth status ; claude auth login ; claude auth logout
- Long-lived token for CI: claude setup-token → store it in the CI secret store as CLAUDE_CODE_OAUTH_TOKEN, never in a file.
- Stored credentials: macOS Keychain; Linux ~/.claude/.credentials.json (mode 600).
- API key from the keychain instead of the environment, in ~/.claude/settings.json:
      "apiKeyHelper": "security find-generic-password -s anthropic-api-key -w"
  (store it once in a terminal: security add-generic-password -s anthropic-api-key -a "$USER" -w)

Settings and harness changes
- Files, strongest last: ~/.claude/settings.json (user) < .claude/settings.json (project, committed) < .claude/settings.local.json (project, not committed) < --settings on the command line.
- Validate JSON after an edit: python3 -m json.tool ~/.claude/settings.json >/dev/null
- Permissions: "permissions": {"allow": [...], "deny": [...]}; deny reading secrets, e.g. "Read(~/.ssh/**)".
- Check the install: claude doctor

On local Ollama (no Anthropic traffic; Ollama 0.14 or newer)
- ANTHROPIC_BASE_URL=http://127.0.0.1:11434 ANTHROPIC_AUTH_TOKEN=ollama ANTHROPIC_API_KEY="" claude --model <ollama-model>
- Add CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 to stop update checks, telemetry and error reports.
- Or: ollama launch claude --model <ollama-model>
- Headless: claude -p "<task>" --model <ollama-model> --permission-mode acceptEdits (edits allowed, other shell commands need --allowedTools)
