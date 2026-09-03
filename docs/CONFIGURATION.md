# secure-agent Configuration Guide

`secure-agent` uses a flexible YAML configuration system. Default configuration rules are embedded into the Go daemon binary and can be customized by creating an overlay configuration file at `~/.config/secure-agent/config.yaml` or passing a `-config <path>` flag to `secure-agentd`.

---

## 📄 File Location

- **Default Overlay Path**: `~/.config/secure-agent/config.yaml`
- **CLI Flag Override**:
  ```bash
  secure-agentd -config /path/to/custom_config.yaml
  ```

---

## ⚙️ Configuration Schema

### `sensitive_globs` (List of Strings)
Glob patterns matching file paths considered sensitive. If an agent process accesses a file matching any of these patterns, a sensitive read event is recorded.

```yaml
sensitive_globs:
  - "**/.env"
  - "**/.env.*"
  - "~/.ssh/id_*"
  - "~/.ssh/*_rsa"
  - "~/.ssh/*_ed25519"
  - "~/.aws/credentials"
  - "~/.config/gh/hosts.yml"
```

---

### `sensitive_paths` (List of Strings)
Directory path prefixes considered sensitive. Any file access within these directory trees triggers a sensitive read event.

```yaml
sensitive_paths:
  - "~/.aws"
  - "~/.ssh"
```

---

### `keychain_markers` (List of Strings)
Path substrings identifying macOS Keychain database files.

```yaml
keychain_markers:
  - "library/keychains"
  - ".keychain-db"
  - "login.keychain"
```

---

### `agents` (List of Agent Objects)
Definitions used by the process tagger to identify AI agent process trees.

```yaml
agents:
  - name: claude
    match: ["claude"]
  - name: cursor
    match: ["Cursor Helper", "cursor"]
  - name: codex
    match: ["codex"]
```

- `name`: Identifier for the agent harness.
- `match`: List of process name substrings or binary name patterns to match against system processes.

---

### `vendor_allowlist` (Map of Agent Name to List of Domains)
Approved egress hostnames and domains per agent harness. Network connections established to domains outside this allowlist following a sensitive file read will trigger a security flag.

```yaml
vendor_allowlist:
  claude:
    - "anthropic.com"
    - "claude.ai"
  cursor:
    - "cursor.sh"
    - "cursor.com"
  codex:
    - "openai.com"
    - "api.openai.com"
```

---

### `net_sample_interval_ms` (Integer)
Frequency in milliseconds at which `libproc` samples active open network sockets for tagged agent processes (default: `2000` ms).

```yaml
net_sample_interval_ms: 2000
```

---

### File & Socket Paths

```yaml
socket_path: "~/.config/secure-agent/daemon.sock"
db_path: "~/.local/state/secure-agent/events.db"
jsonl_path: "~/.local/state/secure-agent/events.jsonl"
```

Tilde (`~`) prefixes are automatically expanded to the user's home directory. Environment variables (e.g. `$HOME`) are also resolved automatically.

### `directory_guard` (Map)

Configures the interactive filesystem guard. The shipped defaults are all `monitor`; the onboarding **Guard My Secrets** opt-in promotes rules via `guard-modes.json`, not this file.

```yaml
directory_guard:
  prompt_deadline_ms: 45000   # how long a prompt-mode hook waits before failing safe to deny
  cwd_overrides:              # per-project policies (first matching prefix wins)
    - cwd_prefix: /Users/me/work/prod-api
      rules:
        env-files: deny
        ssh-keys: prompt
```

Each entry pins a directory subtree to specific rule modes; rules not listed fall back to the global override file, then shipped defaults.

### `fleet` (Map)

Downstream webhook delivery for fleet oversight:

```yaml
fleet:
  webhooks:
    - url: "https://collector.example.com/hooks/secure-agent"
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every payload is signed with `X-SecureAgent-Signature: sha256=HMAC(secret, body)`; delivery retries (500ms/2s/5s) on network errors and 5xx/429 only.

### Proxy authentication

When the proxy is enabled, the daemon generates a per-install token at
`~/.config/secure-agent/proxy-token` (0600). The routing snippet
(`agent-env.sh`) carries it; the proxy rejects unauthenticated proxying with
`407`. The dashboard remains unauthenticated (loopback only).

### Runtime overrides (not in this file)

- `firewall-modes.json` — firewall rules promoted to block, persisted
- `guard-modes.json` — directory-guard mode overrides (onboarding writes this)
- `firewall-sources.json` — user-added fingerprint ingest sources
- `node-id` — stable per-install fleet identity
