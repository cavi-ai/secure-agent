# Changelog

All notable changes to `secure-agent` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [v0.9.0-rc.1] — 2026-09-02

First release candidate. Everything below has CI enforcement: Go (vet, test,
`-race`), Swift package tests, 138 Python hook cases, an end-to-end smoke test
(flag → incident → guard round-trip through a live daemon), and secret
scanning of the repository itself.

> **RC disclaimer.** The DMG is ad-hoc signed: recipients must right-click →
> Open the first time. Notarized builds are planned for v1.0.

### Security hardening

- **Kernel-attested control socket.** Every unix-socket connection is
  identified with `LOCAL_PEEREPID` / `LOCAL_PEERCRED`; a role gate restricts
  reads (owner + agents), guard decisions (agents), and mutations
  (owner-level). Nothing can spoof the menubar or a hook.
- **`/kill` allowlist.** The daemon only kills PIDs it currently recognizes as
  agent processes — the control socket is no longer an arbitrary-process
  killer, and killing the daemon through its own API is impossible.
- **Guard broker bounds.** The pending-prompt queue caps at 32 with an explicit
  `deny("queue-full")` on overflow; identical in-flight requests share one
  waiter; prompts resolve oldest-first.
- **Informed consent.** Guard prompts disclose what "Allow Always" approves
  (`scope_text`): every path under the rule for that agent, not just the file.
- **Filesystem hygiene.** State directories `0700`; database, WAL, and JSONL
  logs `0600`.
- **Web console hardening.** CSP, `X-Frame-Options: DENY`, `nosniff`, and
  `Referrer-Policy` on both the proxy-port and unix-socket dashboard routes.
- **Honest telemetry.** `/fleet` reports a real ldflags-stamped version and a
  stable `node_id`; the fabricated `tailnet_ready` field and the dead
  "synchronous blocker" collector stub were removed.
- **Race fix.** `ProxyServer.port` data race (found by the new `-race` CI job)
  made atomic.

### Directory Guard

- Config-driven `monitor` / `prompt` / `deny` modes across file tools and Bash.
- **Per-project policies**: `directory_guard.cwd_overrides` pins one repo
  subtree to specific rule modes (deny `.env` in the production repo, monitor
  everywhere else) — resolution: cwd overlay → global override → default.
- Native menubar prompts (Allow Once / Allow Always / Deny, with **Deny as the
  safe default**), per-`(agent, rule)` caching, and rule revocation.
- Guard's own control plane is protected from agent writes and from direct
  socket forgery via network clients.

### Fleet oversight

- **Signed webhook delivery** of flags, incidents, and guard decisions:
  `X-SecureAgent-Signature: sha256=HMAC(secret, body)`, 3 retries with backoff
  (network/5xx/429 only), `0600` delivery log, never blocks the daemon.
- **Stable node identity**: 128-bit `node_id` per install, reported by
  `/fleet` and stamped on every webhook envelope.
- **Session identity**: hooks stamp `session_id` (Claude session env or per-run
  UUID) through events → flags → incidents, so evidence chains survive PID
  reuse.
- **CLI parity**: `secure-agent guard list|revoke`, `firewall mode|sources`,
  `events|audit`, plus `SECURE_AGENT_SOCK` for tunneled remote nodes.

### Operator UX

- **`GET /posture`** — the headline: all-clear / attention / critical, a
  `needs_you` count, and severity-ranked items (recent critical flags, pending
  guard prompts, dead collectors, uninspected egress).
- **Incident workflow** — forward-only `open → acknowledged → resolved` with
  audited transitions; reports stay immutable evidence.
- **`GET /events/stream`** — SSE live feed with heartbeat; replaces polling.
- **Console** — posture banner with drill-down links, incident ack/resolve
  buttons, status chips, resolution notes.
- **Onboarding hook self-test** — one click fires a synthetic tool call through
  the installed guard and verifies the round-trip.
- **Human-language guard prompts** — "claude wants to read a cloud credential
  file" with the stakes explained, not a raw path.

### New endpoints (unix-socket API)

`/posture` · `/events/stream` (SSE) · `/incidents/status` · `/guard/*` ·
`/firewall/*` · `/fleet` · `/dashboard/` — full reference in `docs/API.md`.

### Compatibility

- Existing `events.db` files are migrated in place (new columns are additive;
  nothing is rewritten or reinterpreted).
- Everything ships in monitor mode by default: no rule blocks until you
  promote it.

## Earlier

Development history lives in the git log; this changelog starts at the first
tagged release.