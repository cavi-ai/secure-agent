# Configure file and egress protection

[Documentation](README.md) · [Project home](../README.md)

[Getting started](GETTING_STARTED.md) installs the app and the selected hooks. Enable each protection deliberately: hook registration, named guard modes, secret fingerprints and proxy routing are separate controls.

- [Egress firewall and routing](#egress-secret-leak-firewall)
- [Review recurring connections](#review-recurring-connections)
- [Directory Guard and approvals](#directory-guard)
- [Configuration reference](CONFIGURATION.md)
- [Firewall limits](FIREWALL_THREAT_MODEL.md) · [Guard limits](GUARD_THREAT_MODEL.md)

## Egress secret-leak firewall

The firewall inspects routed outbound requests for secret exposure. Its opt-in HTTP/HTTPS proxy listens on `127.0.0.1:8443` by default. For inspected HTTPS hosts it generates certificates with Secure Agent's local CA, scans request streams for credentials, and scans response streams for prompt injection. Enable routing and client CA trust explicitly; tunneled connections remain unopened.

<p align="center">
  <img src="../assets/screenshots/protection-dark.jpg" alt="Protection settings with per-rule monitoring and blocking controls" width="1120">
</p>

Screenshot uses synthetic demonstration data.

**Detection layers** (`daemon/internal/firewall/`):

- **Known-secret fingerprints** — your real secrets, stored only as a salted HMAC (never plaintext), matched even through base64 / url / gzip / JSON encodings.
- **Typed patterns** — Anthropic, OpenAI (incl. project keys), GitHub (classic + fine-grained), GitLab, AWS, Google, Stripe (secret/restricted/webhook), Slack, Twilio, SendGrid, npm, PyPI, DigitalOcean, Doppler, JWT, bearer tokens, private keys, and database connection strings with embedded credentials.
- **Entropy** — a high-entropy backstop (monitor-only).
- **Transcript scanning** — the fingerprint and pattern layers also run over tailed harness transcripts; a hit raises `secret-in-transcript` (severity 3 for a registered secret, 2 for a typed pattern) carrying the rule id, path, and session — never the matched text.

**Credential context.** A credential in the expected auth header to its own vendor host is *legitimate*, not a leak. A secret is flagged only when it goes to a non-vendor host, or lands in a request body / query / non-auth header. This is what makes blocking safe.

**See the control result.** New payload findings distinguish registered fingerprints from typed pattern matches and show the resolved request outcome: **Blocked before forwarding** or **Observed only; delivery unknown**. A monitor-only match can share a request that another rule blocked. Incident reports preserve mixed outcomes as counts of recorded findings, and session exports retain review state, control results, and evidence limits. Older findings retain an unknown outcome. Acknowledgment or reported resolution does not prove credential revocation, repair earlier exposure, or establish remote delivery.

**Monitor by default; earn enforcement.** Every rule runs in `monitor` mode: leaks are reported, nothing is blocked. Promote a rule to blocking once you trust it, through Settings → Egress Firewall or the CLI (applies live):

```bash
secure-agent firewall mode aws-key block
# Return to observation:
secure-agent firewall mode aws-key monitor
```

For YAML policies loaded at daemon start, see [firewall configuration](CONFIGURATION.md#firewall-map). A `firewall.patterns` overlay replaces the full pattern list; changing one existing mode through Settings or the CLI preserves the other detection patterns.

**Route Claude Code through the proxy** with **Settings → Secure Agent → Traffic → Route Claude Code through Secure Agent** (opt-in; no keychain or system-trust changes). The app writes the proxy and Secure Agent's CA (`NODE_EXTRA_CA_CERTS`) into the `env` block of `~/.claude/settings.json`, plus a SessionStart hook that gives each session's Bash commands the tunnel-mode snippet. API requests to the hosts in `proxy_inspect_hosts` (default `api.anthropic.com`) are decrypted and scanned; every other connection passes through unopened, so tools that do not trust Secure Agent's CA (gh, git, curl) keep working. Quitting the app takes the routing back out; while routing is on, start Secure Agent before Claude Code.

Quit Claude Desktop and exit Claude Code before turning routing on or off, then reopen Claude. Secure Agent refuses routing changes while either is running: changing proxy settings in an existing session can leave it using cached certificate or proxy settings. Close routed sessions before quitting Secure Agent as well; removing settings does not reset a running Claude process. If a session reports a certificate or connection error after a routing change, fully quit and reopen Claude.

**Route other agents** by sourcing the tunnel-mode snippet the daemon writes to `~/.config/secure-agent/agent-env.sh` where you launch them (scoped to that shell; every connection passes through unopened):

```bash
source ~/.config/secure-agent/agent-env.sh
```

The snippet carries a per-install proxy token. Proxy requests require that credential; loopback access alone does not grant routing access. Keep the snippet private.

Traffic that bypasses the proxy (pinned or unrouted) is counted as `uninspected_egress` in the status — a **rolling 24h** distinct-endpoint count, so the number reflects the current blind spot instead of growing forever. Clicking the warning (console or posture banner) opens the drill-down: every endpoint with per-agent counts, last-seen, the advisor's verdict, and a one-click **Allow** that records an expected endpoint; it does not decrypt or inspect that traffic (`GET /egress/uninspected` for the raw list).

See [FIREWALL_THREAT_MODEL.md](FIREWALL_THREAT_MODEL.md) for exactly what the firewall defends against, what it does not, and how it handles secret material.

## Review recurring connections

The console's **Protection → Traffic** view groups observed outbound connections by agent activity and destination. A recurring connection from a known agent appears for review when no saved expectation covers it. These observations contain connection metadata; they do not establish what a request contained or whether a destination is safe. Any advisor explanation is labeled as an inference.

Choose an expectation from the observed episode:

| Choice | Scope |
|---|---|
| **Expect this destination** | That agent's exact host, protocol and port. Loopback destinations cannot be saved. |
| **Expect all destinations for this activity scope** | Every destination for the same agent, executable, harness and workspace. Available only when the observed activity scope is complete. |
| **Revoke expectation** | Remove the saved expectation. A recurring episode can return for review on refresh if no other rule covers it. |

Prefer the exact destination when that is the decision you intend. The activity-scope choice also covers future destinations for that scope. Matching exact-destination rules take precedence over broader activity-scope rules.

An expectation changes the episode's review classification. File guards, payload inspection, findings and incident detection continue to apply independently. The **Allow** action in the uninspected-endpoint drill-down uses a separate host allowlist; neither action routes traffic through the proxy or decrypts it.

If an expectation cannot be saved, check the episode's observed agent, destination and scope. An invalid observation is rejected; an unavailable store or inconsistent saved rule produces an error rather than a successful approval. Retry a failed read before relying on the displayed classification. See [Troubleshooting](TROUBLESHOOTING.md#expected-connections-are-unavailable) and the [expected-egress API](API.md#expected-egress-expected-egress).

## Directory Guard

The Directory Guard checks sensitive file access before a supported harness tool executes. Install and register Claude Code or Cursor hooks through [Setup](GETTING_STARTED.md#set-up-your-first-agent).

When an agent tool call touches a guarded path (SSH keys, cloud credentials, the keychain, `.env` files, shell rc files), the hook checks the rule's mode:

| Mode | Behavior |
|---|---|
| `monitor` (default) | The named path rule logs access without a prompt. Independent hard-deny checks still apply. |
| `prompt` | The hook holds the tool call for **Allow Once** or **Deny**. When recorded identity permits it, session and timed access choices require a separate confirmation of the file, tool, workspace, executable path and lifetime. **Inspect session** leaves the request unanswered while its timeout continues. |
| `deny` | Blocked outright, no prompt. |

**Quiet by default.** Every named path rule ships `monitor`. Independent hard-deny checks still block credential-printing and mutations to the guard or harness enforcement plane, even in monitor mode. The **Guard My Secrets** button under Optional capabilities is the explicit opt-in that promotes SSH keys, cloud credentials, the keychain, and harness configuration to `prompt`, written to `~/.config/secure-agent/guard-modes.json`.

**Honest coverage.** The `PreToolUse` hook enforces at the tool-call boundary — it can actually block a `prompt`/`deny` rule before the tool runs. The daemon's `eslogger` telemetry observes a broader slice of file activity (including access outside the hook's reach) but is observe-only there: it can log and correlate, not block.

| Surface | Coverage |
|---|---|
| Claude file tools (`Read`/`Write`/`Edit`/`NotebookEdit`) | Mode-enforced: `monitor` / `prompt` / `deny`, per rule. Writes to harness settings & hook scripts (`~/.claude/`, `~/.cursor/`, `~/.config/opencode/`) are always denied — that's the guard's own enforcement plane. |
| Claude `Grep`/`Glob` | Mode-enforced when the search root is a protected directory (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/Library/Keychains`) — a scan reaches every protected file inside, so the governing rule's mode gates the scan. Broad roots (e.g. `~`) stay ungated; file-level matches inside results are still enforced per call. |
| Claude `Bash` | `deny`-mode rules enforced (protected-directory targets like `cp -r ~/.ssh` included); key material (SSH keys, cloud credential files) always denied via `cat` **or any reader alias** (`grep`/`rg` included — `grep '' credentials` is the same leak). `prompt`-mode paths are also denied — there is no interactive prompt mid-Bash, so a `prompt` rule fails safe to `deny` there instead of asking. |
| Cursor | `Bash` commands only. Cursor's shell-exec payload doesn't carry a `tool_name`, which the file-tool guard needs to tell a `Write` from a `Read`. |

The `harness-config` rule covers the harnesses' own settings and hook scripts. It ships `monitor` (reads logged); **Guard My Secrets** promotes it to `prompt` alongside SSH keys, cloud credentials, and the keychain. Writes are always denied regardless of mode — editing the hook or `settings.json` is how an agent removes the guard watching it.

Writes to `~/.claude/settings.json` and the hook scripts are now denied outright, so the obvious self-removal path is closed — but a determined agent can still probe paths outside the covered harness directories, and the harness's decision to invoke the hook at all can't be enforced from inside the hook. This layer raises the bar; it is not a complete seal.

### Egress after untrusted input

Instructions hidden in content an agent reads (a web page, an image, a response header, an MCP result) can steer it to send data out. The `untrusted-egress` rule does not try to recognize those instructions. It records each session's untrusted inputs (up to 8) and then applies its mode to every later call in that session that can send data out.

Untrusted input:

- `WebFetch` and `WebSearch`
- any MCP tool except `code-review-graph`
- `Read` of an image file (`.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.bmp`, `.tif`, `.tiff`, `.heic`)
- `curl`, `wget`, `http`, `xh` output from a non-loopback host, and `gh` reads (`view`, `diff`, `list`, `checks`, `status`, `api`, `search`)

Egress sinks:

- network clients to a non-loopback host: `curl`, `wget`, `http`, `xh`, `nc`, `socat`, `telnet`, `ssh`, `scp`, `sftp`, `ftp`, `mail`, `sendmail`, `rsync` to a remote
- `git push` and `git send-email`
- `gh pr` and `gh issue` create, comment and edit, `gh pr review`, `gh gist` create and edit, `gh release` create, upload and edit, `gh repo create`, and `gh api` with a body or a non-GET method
- interpreters running inline network code, such as `python3 -c "requests.post(…)"`
- `WebFetch` and MCP `url` arguments with a query, fragment, credentials, an IP host, or a long or token-shaped path segment
- MCP tools whose name starts with a send or write verb (`send_`, `post_`, `reply_`, `forward_`, `create_`, `upload_`, `share_`, `comment_`, `update_`, `fill_`, `type_`, `execute_`, …)

| Mode | Behavior |
|---|---|
| `monitor` (default) | The call runs and the audit trail records `guard-monitor:untrusted-egress`. |
| `prompt` | The Secure Agent prompt names every sink in the call and the inputs the session read, with their origin. With the daemon down, Claude Code asks instead. |
| `deny` | Blocked outright. |

Set the mode in `~/.config/secure-agent/guard-modes.json`, for example `{"untrusted-egress": "prompt"}`, or per project through `directory_guard.cwd_overrides`. The taint record sits beside the daemon socket under `taint/`, which agent tools cannot write, and expires after 7 days.

Each input records where it came from:

| Input | Location | Origin |
|---|---|---|
| Image | the file path | the last commit that touched it (author, email, repository, commit, date, subject), `untracked in <repo>`, or `changed locally since`; the download URL and the app that saved it, when macOS recorded them |
| Web page, download | the URL | the host |
| Web search | the query | web search results |
| MCP tool | the tool name and its URL argument | the MCP server |
| GitHub read | the `gh` command | GitHub |

Git history is read with plumbing commands only, with `core.fsmonitor` and signature checks off, so a repository's own configuration runs nothing.

A send in a tainted session raises one **Data sent after reading untrusted content** finding per session. Its evidence lists every recorded input with its location and origin, then the send and the guard's decision. Later sends fold into it as repeats. The finding is a warning when the send ran (`monitor`, or a Claude Code ask) and informational when it was blocked or you allowed it, so it does not page by default. The session's memory shows **Untrusted input: Image** (or the input's kind) and **Send after untrusted input** rows; locations stay in the finding's evidence.

See [GUARD_THREAT_MODEL.md](GUARD_THREAT_MODEL.md) for the full list of closed bypass classes, the known limits (symlinks, TOCTOU, static inline-code analysis), and exactly which failures fail closed vs. open.

To inspect or revoke a remembered guard decision:

```bash
secure-agent guard list
secure-agent guard revoke claude ssh-keys
```

Revocation forces a new decision for that cached agent/rule pair; it does not undo prior access. Per-project policies and prompt deadlines are documented in [Configuration](CONFIGURATION.md#directory_guard-map).

In **Protection → Rules & permissions**, review session and timed records under **Saved permissions**. **Legacy guard decisions** lists older agent/rule-wide decisions without expiry. File exceptions, expected activity and notification settings have separate effects explained beside each list; revoking one record does not remove other matching policies.
