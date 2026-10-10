# Coverage and evidence

[Documentation](README.md) · [Architecture](ARCHITECTURE.md)

Secure Agent combines several independent sources. A session can have recorded activity without guard hooks, and a guard invocation can exist without inspected outbound traffic. Check the capability you intend to rely on.

## Three separate capabilities

**Guarding** intercepts supported harness tool calls through hooks. Claude Code and Cursor have supported guard integrations. Named rules default to monitoring; independent safety checks can still deny credential-printing and guard/harness mutations. Hook coverage does not make arbitrary shell operations or other harnesses guarded. See [Protection](PROTECTION.md#directory-guard) and the [guard threat model](GUARD_THREAT_MODEL.md).

**Recorded activity** comes from process/network sampling, harness records and optional macOS file telemetry. A transcript collector can identify tool or model activity that process sampling alone cannot. Source support varies by harness; see the [collector table](ARCHITECTURE.md#collectors). File telemetry observes access and does not block it.

**Payload inspection** examines requests routed through the opt-in proxy in inspection mode. Traffic that bypasses the proxy or uses tunnel mode is not decrypted. Network destination observations alone are not payload inspection. See [Protection](PROTECTION.md#egress-secret-leak-firewall) and the [firewall threat model](FIREWALL_THREAT_MODEL.md).

## Interpret coverage states

The API exposes capability support separately from observed state. Setup and the console show the available evidence.

| State | Meaning | Next step |
|---|---|---|
| `observed` | Activity for this capability was seen | Inspect the evidence and time; do not extrapolate to the entire session |
| `not-observed` | No matching activity has been seen | Run a small supported task, then refresh |
| `unsupported` | This source does not support that capability | Review the harness's other available sources |
| `unattributed` | Evidence cannot be assigned to this session | Inspect machine-level evidence separately |
| `off` | The capability is disabled | Enable it only if you need it, then check again |
| `stale` | A failed refresh leaves last-known evidence | Repair or retry the named source before relying on freshness |

An installed-hook check verifies setup and a daemon round trip. An observed invocation verifies that invocation. Neither establishes complete protection. Current proxy observations can lack session identity, so machine-level inspection hits may not establish a session's payload coverage.

## Findings, decisions and actions

A finding records a detected condition and its evidence. Monitoring records findings without turning every one into a blocking decision. Guard prompts, firewall blocking and resource interventions have their own policies and enablement steps.

A decision or exception has a scope. Review that scope before allowing a path, marking traffic expected or muting a finding. Cached guard decisions can be revoked; see [Protection](PROTECTION.md). Local advisor recommendations do not authorize commands. Local chat actions require the confirmation described in [Local chat and commands](SYSTEM_AGENT.md).

## Local data and optional connections

The daemon stores monitoring data locally. The console reads through an authenticated local listener, while the CLI uses an owner-scoped Unix socket. Local chat and the advisor use configured loopback model servers. Optional fleet webhooks and OTLP export send configured telemetry outside the node; enable and secure them deliberately. See [Security](../SECURITY.md), [API authentication](API.md#peer-authentication--endpoint-roles) and [Fleet](FLEET.md).

Use [Your first observed session](FIRST_SESSION.md) to connect these concepts to one small task.
