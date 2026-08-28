# Egress Secret-Leak Firewall — Threat Model

This document states plainly what the firewall defends against, what it does not,
and the trust assumptions it makes. An honest boundary is part of the security
guarantee: a tool that overstates its coverage is worse than one that names its
blind spots.

## What it defends against (in scope)

Accidental exfiltration of the user's real secrets in agent-originated egress —
a known secret or a well-typed credential leaving in a request header, body, or
query to a destination where it does not belong. This is the class of mistake
that forces repeated key rotation.

Concretely, the firewall inspects agent HTTPS traffic that transits its local
proxy and flags (monitor mode) or blocks (a promoted rule) when it sees:

- a **registered secret** (matched by salted-HMAC fingerprint, even through
  base64 / url / gzip / JSON encodings) leaving to any non-vendor destination;
- a **typed credential** (Anthropic, OpenAI, GitHub, AWS, Google, Stripe, Slack,
  JWT, bearer token, private key) going to a non-vendor host, or appearing in a
  request body / query / non-auth header rather than the expected auth header.

A credential in the expected auth header to its own vendor host is treated as
legitimate, not a leak. That distinction is what makes blocking safe.

## What it does NOT defend against (out of scope)

- **A determined malicious agent.** An agent that actively wants to exfiltrate
  can encrypt or steganograph a payload, or route egress around the proxy. The
  firewall raises the cost and catches accidents and low-effort exfil; it does
  not claim to stop a motivated adversary.
- **TLS-pinned traffic.** A client that pins its certificate cannot be
  intercepted by the local MITM proxy. The firewall fails **open** (never blocks
  what it cannot inspect) and records the connection as uninspected, rather than
  breaking the agent.
- **Non-proxied egress.** An agent that ignores the proxy environment connects
  directly. Such connections are counted in the `uninspected_egress` status
  metric so the blind spot is visible, not silent.
- **Filesystem / directory access.** Guarding what an agent reads or writes on
  disk is handled separately by the harness hooks, not by this firewall.
- **Secrets the user never registered and that match no pattern.** Fingerprints
  cover registered secrets; typed patterns cover known shapes; entropy is a
  low-confidence backstop. A novel, unregistered, pattern-less secret can slip.

## Trust assumptions

- The daemon and its CA private key are trusted and run as the user. The CA key
  is written `0600` and is local to the install; uninstalling removes it.
- Routing is **opt-in and scoped to the shell** the user configures. The
  firewall never installs a CA into the system trust store and never edits a
  shell rc; it writes a snippet the user chooses to source.
- The HMAC salt is per-install and never exported, so fingerprints are not
  portable across machines and cannot act as a shared secret oracle.

## Handling of secret material

- Registered secrets are stored **only** as `HMAC-SHA256(salt, value)` plus type
  and length. Plaintext is discarded during ingest and never persisted.
- Findings and events carry a secret's **type** and the matching rule/fingerprint
  **id** — never the secret value.
- On any inspection error, timeout, or un-decodable payload the firewall allows
  the request and records a finding; it never fails closed.

## Posture

Every rule ships in `monitor` mode: leaks are reported, nothing is blocked. An
operator promotes a rule to `block` only after its per-rule stats
(`would_block` with zero confirmed false positives) show it is safe. This is the
whole reason the firewall can be trusted to enforce without breaking agents.
