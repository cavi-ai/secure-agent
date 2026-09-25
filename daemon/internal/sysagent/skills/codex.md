---
title: Codex CLI — sign-in, config and local models
summary: Sign the Codex CLI in with ChatGPT or an API key, keep credentials in the OS keyring, set its sandbox, and run it on local Ollama.
keywords: codex, openai, codex login, chatgpt login, openai_api_key, config.toml, sandbox, approval, oss, local-provider, codex exec
---
Rules
- codex login opens a browser (or shows a device code with --device-auth): terminal work for the operator.
- An API key is piped from the environment or a password manager, never typed into chat or a file.
- Never run with --dangerously-bypass-approvals-and-sandbox or sandbox_mode = "danger-full-access".

Sign-in
- codex login status ; codex login ; codex login --device-auth ; codex logout
- API key: printenv OPENAI_API_KEY | codex login --with-api-key
- Keep credentials in the OS keyring instead of ~/.codex/auth.json, in ~/.codex/config.toml:
      cli_auth_credentials_store = "keyring"

Config (~/.codex/config.toml, or $CODEX_HOME/config.toml)
- sandbox_mode = "workspace-write"        # edits inside the working folder only
- approval_policy = "on-request"
- [sandbox_workspace_write]
  network_access = false
- check_for_update_on_startup = false

On local Ollama (no OpenAI traffic; Ollama 0.13.4 or newer)
- Interactive: codex --oss --local-provider ollama -m <ollama-model> --sandbox workspace-write
- Headless: codex exec --oss --local-provider ollama -m <ollama-model> --sandbox workspace-write --skip-git-repo-check "<task>"
- Default in config.toml: oss_provider = "ollama"
- A model that is not pulled yet is downloaded from ollama.com on first use: pull it yourself first (ollama pull <model>).
