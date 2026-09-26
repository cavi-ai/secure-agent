---
title: OpenClaw — onboarding, provider auth and local models
summary: Onboard OpenClaw on local Ollama, manage provider logins and keys, tighten its shell policy, and run one-shot tasks headless.
keywords: openclaw, clawdbot, moltbot, openclaw onboard, openclaw.json, openclaw models auth, gateway, tools.exec, exec approvals, agent exec
---
Rules
- Logins (openclaw models auth login) and onboarding are interactive: terminal work for the operator.
- Keys go in through openclaw models auth paste-api-key or the trusted ~/.openclaw/.env, never into chat, a workspace .env or a repository.
- Keep shell commands gated: tools.exec.mode "ask" (or "allowlist") rather than "full".

Onboarding on local Ollama
- Interactive: openclaw onboard → choose Ollama, "Local only".
- Config ~/.openclaw/openclaw.json (JSON5; OPENCLAW_CONFIG_PATH overrides it), native Ollama URL with no /v1:
      models: { providers: { ollama: { baseUrl: "http://127.0.0.1:11434", apiKey: "ollama-local", api: "ollama" } } },
      agents: { defaults: { model: { primary: "ollama/<model>" } } }
- Or: ollama launch openclaw --model <model>

Provider logins (cloud models only)
- openclaw models auth login --provider <id>
- openclaw models auth paste-api-key --provider <id>
- Credentials are kept in OpenClaw's state under ~/.openclaw; list what is configured with openclaw models status.

Policy and checks
- tools.exec.mode: deny | allowlist | ask | auto | full
- openclaw security audit
- No automatic updates: OPENCLAW_NO_AUTO_UPDATE=1 and update.checkOnStart: false

Headless one-shot
- openclaw agent exec "<task>" --model ollama/<model> --cwd <folder> --json
  (temporary state, exits 0 ok / 1 error / 2 timeout; --config <file> pins the config)
- Interactive without a Gateway: openclaw chat --message "<task>"
