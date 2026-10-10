# Connect a fleet

[Documentation](README.md) · [Project home](../README.md)

Use this guide to connect a running node to a collector. For a macOS node without the menu bar, [install the per-user service](GETTING_STARTED.md#linux-and-headless-nodes). Linux nodes run the Go daemon directly or under your own service manager.

The reference collector is an HTTP listener, bound to loopback by default. For remote nodes, put it behind a TLS endpoint and configure read authentication before exposing telemetry. Set `SECURE_AGENT_COLLECTOR_READ_TOKEN` in the collector environment or use `-read-token`; a non-loopback bind without a read token leaves read endpoints unauthenticated. Webhook HMAC authentication and read authentication are separate.

The fleet contract is two sides: each node pushes signed webhooks, and a collector rolls them up.

**Node side** — one command enrolls this machine into a collector:

```bash
secure-agent fleet enroll https://collector.internal:9445
```

Enroll reads the node id from the running daemon, generates the shared secret, merges the webhook into `~/.config/secure-agent/config.yaml` (backup written first), and prints the single line to append to the collector's secrets file. The daemon hot-reloads fleet config — deliveries begin within seconds, **no daemon restart**. (Manual setup still works; the equivalent `config.yaml` block is below.)

```yaml
fleet:
  hostname: "builder-01"                      # display name (default: os.Hostname)
  labels: { env: prod, role: build-runner }   # grouping dimensions for fleet views
  heartbeat_interval_sec: 60                  # status cadence (default 60)
  webhooks:
    - url: "https://collector.internal:9445/hooks/secure-agent"
      secret: "<shared-secret>"
      events: [flag, incident, guard]   # empty = all
```

Every flag, incident, and guard decision is POSTed as an envelope:

```json
{"node_id": "00000000000000000000000000000001", "kind": "flag", "ts": "2026-01-01T00:00:00Z", "version": "<daemon-version>", "boot": "example-boot", "seq": 42, "payload": {}}
```

with `X-SecureAgent-Signature: sha256=<hex hmac-sha256(secret, body)>` and `X-SecureAgent-Node: <node_id>` headers. `boot` + `seq` are the node's gap-detection coordinates: every delivery is numbered per daemon run, so a dropped delivery (backlog cap, collector downtime, restart) surfaces at the collector as a **sequence gap** — best-effort delivery, but never *silent* loss.

Nodes also push a **`status` heartbeat** — at boot, on the interval, and immediately on posture-state changes — carrying the node's own `/posture` headline (`posture_state`, `posture_summary`, `needs_you`) plus hostname, labels, and agent count. The heartbeat bypasses the `events:` filter on purpose: liveness you can unsubscribe from is indistinguishable from a dead node. This is what lets the collector answer the two fleet questions that matter — *"is anything critical anywhere?"* and *"is every node alive?"*

**Collector side** — the reference collector in this repo (`cmd/secure-agent-collector`, stdlib-only):

```bash
make collector
# provision one secret per node, then run (loopback by default):
umask 077
printf '%s\n' '<node-id-1>=<secret-1>' > secrets.txt
./bin/secure-agent-collector -addr 127.0.0.1:9445 -store ~/.local/state/secure-agent-collector -config secrets.txt
```

- `GET /fleet` — merged multi-node rollup ordered by operator priority (critical → attention → stale → all-clear): version (tracks the newest report), liveness vs. last-activity timestamps, **rolling 24h counts** (`flags_24h`, `critical_flags_24h`, `incidents_24h`), guard allow/deny breakdown, sequence-gap count, and each node's posture headline
- `GET /fleet/rules` — **cross-node rule aggregation**: which flag rules are firing, on how many of the fleet's nodes ("`sensitive-read-then-connect` — 5/12 nodes, 3 critical in 24h"). One node is an incident; five is a bad release.
- `GET /fleet/sessions` — cross-node session records when nodes opt into `session` and `trace` delivery
- `GET /nodes/<id>/events?kind=flag&limit=50` — one node's stored envelopes
- `GET /` — dark overview page: fleet headline (*"2 critical · 1 stale · 12 all-clear"*), the rules-across-fleet table, and per-node cards titled by hostname with posture chips, label chips, and delivery-gap warnings
- `GET /healthz` — liveness

Liveness is heartbeat-aware: nodes sending `status` are stale after 3 missed minutes and "gone quiet" after 10; legacy event-only nodes keep the lenient 10/20-minute thresholds.

Signatures are verified constant-time; unsigned, tampered, wrong-node, and unknown-node traffic is rejected. Deliveries retry (500ms/2s/5s) on network errors and 5xx/429 only; failures land in the node's `webhook-deliveries.jsonl`.

The whole chain — node → signed webhook → verified envelope (flag **and** heartbeat) with contiguous sequence numbers → posture-aware rollup — plus the `fleet enroll` CLI flow, is covered by `packaging/test/e2e_smoke.sh` in CI.

Treat the enrollment output and `secrets.txt` as credentials. Provision the real node/secret pairs privately; the placeholders above are not working credentials. The collector reads the secrets file at startup, so restart it after provisioning a new node. Its append-only JSONL store uses `0600` files inside a `0700` directory.

See [fleet configuration](CONFIGURATION.md#fleet-map) for hostname, labels and subscriptions, and the [collector API reference](API.md#reference-collector-cmdsecure-agent-collector) for the envelope and endpoint contracts.
