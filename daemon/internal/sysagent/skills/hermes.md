---
title: Hermes Agent — providers, keys and local models
summary: Point Hermes Agent at local Ollama, manage provider credentials with hermes auth, keep approvals on, and run one-shot tasks.
keywords: hermes, hermes agent, nous, nous research, hermes auth, hermes model, config.yaml, custom endpoint, hermes -z, approvals, yolo
---
Rules
- hermes auth and hermes setup are interactive: terminal work for the operator.
- Keys go in through hermes auth add or hermes config set <KEY> in a terminal (they land in ~/.hermes/.env), never in chat.
- Never run with --yolo or HERMES_YOLO_MODE=1; keep approvals.mode manual.

Local Ollama as the provider
- hermes model → Custom endpoint → http://127.0.0.1:11434/v1, leave the key blank.
- Or in ~/.hermes/config.yaml ($HERMES_HOME/config.yaml):
      model:
        provider: custom
        base_url: http://127.0.0.1:11434/v1
        default: <model>
- Hermes needs at least a 64k context, which Ollama's /v1 API cannot set per request: serve with OLLAMA_CONTEXT_LENGTH=64000 ollama serve.

Credentials
- hermes auth status ; hermes auth list ; hermes auth add ; hermes auth remove ; hermes auth logout
- API keys: ~/.hermes/.env ; OAuth logins: ~/.hermes/auth.json

One-shot and interactive
- Headless: CUSTOM_BASE_URL=http://127.0.0.1:11434/v1 hermes -z "<task>" --provider custom -m <model>
  (prints only the final answer; exit 0 ok, 1 no text, 2 failed)
- Keep writes inside a folder: HERMES_WRITE_SAFE_ROOT=<folder>
- Interactive, seeded with a first message: hermes chat --provider custom -m <model> -q "<task>"
