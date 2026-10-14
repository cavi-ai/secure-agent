# Hook history

[Documentation](README.md) · [Session workflows](USAGE.md)

The session Hooks view summarizes recorded completions: runs, execution errors,
cancellations, blocks, returned characters and cumulative runtime. Unknown
measurements are shown separately from measured zero. Claude Code completions come from transcripts.
Codex completions come from an existing host forwarding app-server notifications.
OpenClaw, Hermes and OpenCode hosts forward individual handler completions to
their native result adapters.
An empty history does not establish that no hooks ran.

## Actionable findings

Current session status and the Hooks view assess the latest 1,000 retained
completions within 30 minutes, with up to 20 findings. The view reports when
the sample is limited. Completions without a stable handler identity remain
in history but cannot support handler-specific diagnoses.

- **Repeated execution errors:** three consecutive observed errors for one
  handler and configuration produce a repair finding. Later success,
  cancellation or a new observed configuration ends that pattern. Cancellation
  is not treated as evidence of repair. Live-session repair findings also appear
  in Attention and link to the exact session.
- **Repeated blocks:** three consecutive block decisions for the same
  host-correlated action produce an advisory. They may represent correct
  protection or a validation retry; overall task progress remains unknown.
- **Slow foreground callbacks:** three consecutive measured foreground runs
  of at least 2,000 ms produce an optimization advisory. Durations may overlap
  and do not measure total task delay.
- **Substantial context:** three consecutive measured contributions of at
  least 10,000 context characters produce a scope-review advisory. Character
  counts do not establish token cost, duplicate content or malicious injection.

Each finding shows its evidence window, handler, configuration when known,
observed consequence, next action and limitations. A security role and the
associated action outcome are displayed only when reported by the forwarding
host. Neither hook names nor successful completions establish protection
coverage. The thresholds above are fixed diagnosis defaults, not security
policy or automatic permission changes.

## Ingestion diagnostics

### Delivery issues in Attention

Recent, valid host reports with active source, capture, delivery or persistence
errors create one Attention item per forwarding instance. Inspect delivery opens
the same assessment used by session diagnostics, including queue counts,
persistence when reported, safe error codes and specific recovery guidance.
Explicit session scope is retained; an unscoped host report does not borrow a
session, workspace or process identity.

Backlog, cumulative delivery failures, an intentional source disconnect and a
previous failed report attempt do not by themselves create an active alert. A
new report clearing the active errors removes the alert. Reported drops remain
a separate evidence gap. Stale or unverified error reports move to monitoring
coverage as unknown; they are never described as recovered. Reports and these
assessments describe the current daemon run, not a durable incident history.

### Inspecting recorded evidence

Findings and attributed history groups link to their recorded runs. The evidence
drawer reads up to 100 matching completions from the last 30 minutes, filtered
by the exact session, harness, event, script, handler and configuration. It
shows outcomes, safe reason codes, reported action outcomes and measured values;
unknown measurements remain unknown. Older rows without handler identity can
be inspected as their event/script group without creating a handler diagnosis.

Truncation and the evidence window are visible. Equal timestamps do not establish
execution order. An empty window or a failed read does not confirm recovery or
prove that no hooks ran. Refresh evidence reloads metadata; it does not rerun a
hook or change policy. Commands, source paths and output text are not returned.

The read-only endpoint is `GET /sessions/{id}/hook-evidence`. Required query
parameters are `harness` and `event`; `event_scope=exact` selects the full event
label for a finding. The default `event_scope=group` matches a history group’s
event name before its optional tool suffix. Optional `script`, `handler_id` and
`config_id` default to the empty value of that exact history group, not a
wildcard. Unknown or repeated parameters return 400. Storage errors return 503.
The response includes the filter, window, rows and a truncation indicator.

### Setup and verification

Hook setup and verification is available from Home monitoring coverage, the
Hooks view and the delivery inspector. It covers Claude Code, Codex, OpenClaw,
Hermes and OpenCode. Claude
reads retained transcript completions; the other sources require the existing
host to forward the individual completions it observes. OpenCode requires the
supported v2 protocol. The guide explains those boundaries and shows last-known
daemon receipts when available.

Confirm a real completion during normal use, then inspect its session history
and delivery diagnostics. Configured hooks, setup steps and connected reports
alone do not establish complete delivery or protection coverage. The guide does
not install runtime integrations or generate synthetic completion evidence.

### Daemon receipts and rejections

Current session status and the Hooks view include expandable daemon ingestion
diagnostics across all sessions. They show accepted deliveries by harness and
the last local receipt time, plus a global count and last time of recognized
shared hook records rejected by validation. Rejected payloads and their claimed
session or harness identities are not retained in these diagnostics.

Counters begin when diagnostics are enabled in the current daemon run and reset
when the daemon restarts. Receipt means the collector delivered an event for
processing; durable storage is reported separately by storage health. Delivery
retries can count again even when history deduplicates the execution.

No observations do not establish a broken forwarder. Host connectivity remains
unknown without host evidence. Errors before a shared record reaches the daemon,
including recorder input and output failures, are visible only if the host
explicitly reports them. For rejected
records, check the host and recorder diagnostics, validate the shared format,
and retry retained completions with their original delivery IDs.

## Host forwarding reports

Hosts may send optional `hook_forwarder` reports alongside completions to
`secure-agent hooks record --format codex`. The same shared report works with
the other recorder formats; its harness must match the selected format, except
`--format record`, which accepts all supported harnesses. Codex app-server
notifications do not supply this report: the forwarding host must produce it
from its own source subscription and delivery queue.

```json
{
  "type": "hook_forwarder",
  "version": 2,
  "harness": "codex",
  "forwarder_id": "forwarder-instance-uuid",
  "sequence": 1,
  "ts": "2026-10-13T10:00:00Z",
  "state": "error",
  "pending": 3,
  "delivery_failures": 2,
  "dropped": 0,
  "health": {
    "source_state": "connected",
    "delivery_error": "recorder-failed",
    "report_error": false,
    "outbox": { "persisted": 3, "recovered": 0 }
  }
}
```

Version 2 reports separate source connection, capture, delivery and persistence
health for every harness. Version 1 reports remain readable, with detailed
health shown as unavailable. Report versions are independent of completion
record versions. The shared forwarding client emits version 2 reports and
requires a recorder that accepts them; an older recorder rejecting reports
leaves reporting errors visible locally. Completion delivery is independent.

`health.source_state` is the host's source observation. Aggregate `state` is
`error` when capture, delivery or outbox errors are active; otherwise it matches
the source state. A connected source can coexist with failed delivery or
persistence. Optional error fields accept only these safe codes:

| Stage | Codes | Recovery |
| --- | --- | --- |
| Capture | `invalid-input`, `unsupported-protocol` | Correct the completion metadata or native protocol and required snapshots. |
| Capture | `scope-mismatch`, `delivery-conflict` | Use the correct harness/session forwarder and preserve identical metadata for each retry ID. |
| Capture | `queue-full` | Restore delivery and let the queue drain; rejected completions may be unrecoverable. |
| Delivery | `recorder-unavailable` | Restore the recorder executable and its permissions. |
| Delivery | `recorder-failed` | Check the recorder and output storage, then retry retained completions with their original IDs. |
| Persistence | `outbox-full`, `outbox-failed` | Restore storage access, free space or increase the budget; preserve the existing outbox. |

Capture errors clear after a valid admission, including an identical pending
retry. A queue-full error also clears when delivery frees capacity. Delivery
and persistence errors clear only after their respective operations succeed.
Unrelated messages and hook execution outcomes do not clear forwarding errors.
Failures and drops remain cumulative after recovery.

With an outbox enabled, `persisted` is the subset of `pending` confirmed on disk;
`recovered` is the number loaded when this host instance opened its outbox and
does not decrease as deliveries drain. Both counts are required, including
zero. Omitting `outbox` in version 2 means persistence is disabled; queued
completions may be lost on host exit. In version 1, persistence is unknown.
`report_error` is required and describes the preceding report attempt. A
received report carrying this flag shows reporting has resumed; an ongoing
report outage is visible only in the host's local diagnostics. Shutdown
cancellation does not create a reporting or completion-delivery failure.

Use a globally unique opaque `forwarder_id` for one reporting instance and
scope, with a new ID after restart or a session-scope change. An optional opaque
`session_id` explicitly scopes the host's report; omitting it leaves session
attribution unknown. Reports do not create sessions or hook runs. Never send
commands, source paths, output text, credentials or raw errors in this contract.

`sequence` starts at 1 and increases for each new snapshot. Retry a snapshot
with its original sequence and timestamp; duplicate or older sequences do not
refresh receipt time. `pending` is the current number of queued completion
deliveries. `delivery_failures` counts failed completion delivery attempts,
including retries; `dropped` counts completions discarded by the host. Both
counters are cumulative for the reporting instance and cannot decrease. All
three counters are required, including measured zero; integers must be at most
9,007,199,254,740,991.

`connected` reports a connected hook-source subscription. `disconnected` reports
a disconnected source. `error` reports an active source or delivery problem.
These are host observations, not independently verified connection states.
Send a new report on state changes and about every 30 seconds while active.
Reports become stale after two minutes without a new receipt or when the host
timestamp is older than two minutes. Freshness requires a host timestamp no
later than its original local receipt; a future timestamp remains unverified
until a newer valid report arrives or the receipt becomes stale. Stale and
unverified reports leave the current connection state
unknown; they do not establish disconnection or disabled protection.

The daemon retains at most 128 recently received forwarder instances in memory,
with a visible truncation indicator when others have been omitted. Reports reset
on daemon restart. Older hosts remain unknown. A connected report does not
establish complete delivery, erase cumulative drops or prove protection coverage.
For queued deliveries or an active error, check the host and recorder and retry
retained completions with their original delivery IDs. Dropped completions may
not be recoverable.

## Shared host delivery client

Go hosts can embed `daemon/hookrun/forwarder` to keep recorder I/O off their
hook callback. `NewCodex` accepts native app-server notifications through
`Submit`; it assigns one opaque execution ID, normalizes metadata immediately,
and retains that same metadata and ID for retries. Unrelated notifications are
ignored. Raw output and source paths are never queued.

```go
client, err := forwarder.NewCodex(forwarder.Config{
    Sender: forwarder.Recorder{Executable: recorderPath},
})
```

OpenClaw, Hermes and OpenCode hosts use `NewAdapter` with their native decoder
and the same client configuration, lifecycle, diagnostics and retry behavior:

```go
client, err := forwarder.NewAdapter(forwarder.Config{
    Harness: "hermes",
    Sender: forwarder.Recorder{Executable: recorderPath},
}, hermes.Decoder{})
```

Use `openclaw.Decoder{}` or `opencode.Decoder{}` with the matching harness for
those hosts. `Submit` accepts the documented per-handler completion envelope,
including its host-assigned execution ID. Identical pending retries do not add
queue entries. `NewCodex.Submit` instead accepts a native notification and
assigns the delivery ID once. Hosts already supplying normalized metadata can
use `NewAdapter` with `hookrun.RecordDecoder{}`, or call `Client.Enqueue`.
Input to either adapter is limited to 1 MiB. `hookrun.ErrorCode(err)` extracts
the safe diagnostic code without parsing error messages. Claude transcript
collection remains independent of host forwarding and does not imply a source
subscription or an outbox.

`recorderPath` must be the absolute path to the installed `secure-agent` CLI.
An optional `Recorder.Output` selects the activity log; configure the daemon to
tail that path. Run `client.Run(ctx)` in a host-owned background worker and
observe its result. Call `client.Submit(notificationJSON)` once per native
completion in the existing notification callback. A returned error must remain
visible in host diagnostics without changing the hook's result. Do not resubmit
the notification for client-owned retries: doing so allocates a new execution
ID. A full queue returns `ErrFull`, counts the rejected completion as dropped,
and preserves previously accepted completions.

Call `SetSourceState("connected")`, `SetSourceState("disconnected")`, or
`SetSourceState("error")` from the actual subscription lifecycle. Initial source
state is unknown; no host report is emitted until the host supplies a state.
Completion traffic and stopping the delivery worker do not establish source
connectivity. The client sends reports on changes and every 30 seconds while
running. `Snapshot()` exposes pending deliveries, cumulative failures and drops,
worker state, and report errors locally, including during a recorder outage.
Reports use the same delivery path, so an unavailable recorder cannot carry
fresh diagnostics to the console until it recovers.

Defaults are 256 queued completions, a one-second retry delay, and a ten-second
timeout per send. Capacity includes the in-flight completion and is capped at
4096. Capture never waits for recorder I/O; new completions cannot bypass a
failed delivery's retry delay. By default the queue is in memory: releasing the
client or exiting the host loses pending metadata. Cancellation retains pending
records for another `Run` on the same client. Each new client has a new reporting
ID. An optional durable outbox preserves confirmed records across host restarts.

The recorder transport waits for process exit after each metadata record.
Success confirms an activity-log append, not fsync, collector receipt, or
database persistence. Uncertain failures can cause duplicate appends; stable
execution IDs let stored hook history deduplicate them. Delivery recovery clears
the active delivery error but preserves cumulative failures and drops.

### Durable outbox

Set `Config.OutboxDir` to a stable absolute directory dedicated to one client
scope. The client creates missing directories privately. Existing directories
must be owned by the current user and have no group or other permissions. One
client owns an outbox until `Close`; concurrent owners and a changed harness or
session scope are rejected. Do not share an outbox between independent hosts.

Capture still performs no disk I/O. A separate worker commits normalized
metadata to SQLite with full synchronization, even while recorder delivery is
blocked. `Snapshot.Pending` counts all queued completions; `Persisted` is the
subset confirmed in the outbox. A successful `Submit` or `Enqueue` confirms
memory admission only. A crash can lose records not yet confirmed persisted.
`StorageError` and `StorageFull` identify local persistence or acknowledgment
problems; affected records remain pending. Capacity overflow remains an explicit
drop. Storage errors do not count as failed recorder delivery attempts.

The database budget, `OutboxMaxBytes`, defaults to 8 MiB, with a minimum of
64 KiB and maximum of 1 GiB. SQLite enforces the budget in whole pages and reclaims
freed pages. Rollback journals require temporary space in addition to the
database budget. A full outbox retains unsaved records in the bounded memory
queue and retries storage; it never evicts accepted records to make space.

The recorder transport uses `hooks record --durable` for outbox completions.
It confirms success only after syncing the activity file and its directory.
Durable appends include a newline separator so a torn earlier append cannot
swallow a replayed completion; the collector ignores empty separator lines.
Only this durable acknowledgment permits removing the outbox entry. An older
recorder that rejects `--durable` leaves the entry pending. Custom transports
must implement `DurableSender` with the same storage acknowledgment guarantee.
This confirms durable activity-log delivery, not collector receipt or durable
database ingestion.

On restart, reopen the same outbox and scope. `Recovered` counts the records
loaded at open. Execution IDs survive restart; the new reporting instance gets
a new ID, unknown source state, and new per-instance failure/drop counters.
Stop and join `Run` before `Close` releases ownership. Wait for
`Persisted == Pending` before graceful shutdown if captured records must survive;
`Close` reports `ErrUnpersisted` when memory-only records remain. Unsupported,
corrupt, over-budget, or mismatched outboxes are preserved and rejected rather
than silently reset. Fix the reported storage/configuration issue and reopen.

Other Go hosts use `New` with their harness and call `Enqueue` with validated
shared records from their adapter. Set `SessionID` only for a client dedicated
to one session; otherwise reports cover the host's reporting instance. Custom
`Sender` implementations must honor context cancellation and acknowledge actual
destination acceptance, rather than merely accepting a write to a pipe.

## Forward Codex completions

Run the recorder as a separate consumer of the host's event stream:

```sh
secure-agent hooks record --format codex
```

It reads one JSON envelope per line from stdin and appends metadata to
`~/.local/state/secure-agent/activity.jsonl`, which the daemon already tails.
`--output path` selects another file; configure the daemon to tail that file if
you use it. Start the daemon before forwarding events. Existing checkpointed
files resume from their saved offsets; an uncheckpointed file starts at its end.

Wrap each `hook/completed` notification in an envelope:

```json
{
  "id": "completion-uuid",
  "notification": {
    "method": "hook/completed",
    "params": {
      "threadId": "thread-uuid",
      "run": {
        "id": "pre-tool-use:0:/path/to/hooks.json",
        "eventName": "preToolUse",
        "status": "completed",
        "completedAt": 1791882001,
        "durationMs": 12,
        "entries": []
      }
    }
  }
}
```

The `notification` is the host's original app-server v2 notification. Assign the
envelope `id` once per completion, before queuing it, and reuse that ID for every
retry. Use a UUID or another opaque identifier. Codex's `run.id` identifies the
configured handler, repeats between executions and can include a source path.
It is unsuitable as a completion ID. The adapter derives an opaque handler ID
from this native ID; the raw value is not stored. Separate configured handlers
therefore stay separate even when their script labels are missing.

The derived ID is `codex-handler:` followed by the SHA-256 digest of
`secure-agent:codex:handler:v1`, a zero byte, and the native `run.id` in UTF-8.
The adapter preserves an explicit host-supplied `evidence.handler_id` instead
when present. Missing or null native IDs remain unattributed unless the host
supplies an identity. The adapter never substitutes a delivery ID, source path
or script basename for a missing native handler ID.

Identity follows Codex's configured-handler ID and can change if Codex reorders
or relocates that handler. Configuration revisions still require a host-supplied
`config_id`; a stable handler ID does not establish an unchanged configuration.
Hosts can provide their own durable inventory identity to span such changes.

Completion notifications do not identify the executed command. If the host has
a trusted mapping from its hook inventory, it may include an optional envelope
`script`, such as `guard.py`. Only a basename is accepted. Without it the console
shows **not recorded**. Records lacking handler identity are combined by event
and script; identified handlers retain their own rows.
The recorder never treats a configuration filename as the executed script.

`completed` becomes `ok`, or `inject` when it returned model-facing text. `failed`
becomes `error`; `blocked` and `stopped` become `block`. Character counts include
context, feedback and stop entries, using Unicode characters. Diagnostic errors,
UI warnings, status messages, source paths and output text are not persisted.
Start notifications and unrelated app-server messages are ignored. Invalid
completions, unsupported outcomes and input lines over 1 MiB stop the recorder
with a nonzero exit status; errors do not echo the rejected input.

Hosts should queue forwarding independently from hook execution. A recorder
failure must remain visible to the host without changing the hook's result or
blocking the agent's tool call. Retry the same envelope after reconnecting. The
host owns completion IDs and delivery; the recorder does not launch Codex,
subscribe to another client's events, or recover historical runs from rollouts.
Codex's current rollout policy omits hook lifecycle events.

## Forward OpenClaw, Hermes and OpenCode results

Use `secure-agent hooks record --format openclaw`, then `--format hermes` or
`--format opencode` for the corresponding host. These adapters consume this
Secure Agent host envelope; it is not an upstream notification protocol:

```json
{
  "type": "hook_completed",
  "version": 1,
  "harness": "openclaw",
  "id": "completion-uuid",
  "session_id": "session-uuid",
  "ts": "2026-10-13T10:00:00Z",
  "event": "before_tool_call",
  "state": "completed",
  "duration_ms": 9,
  "result": {"block": true, "blockReason": "Denied"}
}
```

The host captures one invocation at its handler execution boundary, after
applicable policy filtering. Use the durable session ID, not a session routing
key, process ID, or tool-call ID. Assign `id` once per handler invocation and
reuse it on retries. Supply the completion timestamp and measured handler
duration. Optional `script` is a basename. Hook names use their native dot or
underscore spelling. The adapters cover plugin callbacks; the separate
OpenClaw internal-hook and Hermes gateway-hook dispatchers are not covered.

`state` describes the callback: `completed`, `error`, or `cancelled`. The status
of a tool, model call or agent mentioned inside its input does not describe the
callback. Exceptions remain errors even when the runtime fails closed. Approval
requests are not counted as denials. Results are discarded after normalization;
only the common metadata record reaches the activity log. Project only the
native fields needed below, and keep forwarding on a separate queue so recorder
errors cannot change hook behavior.

| Adapter | Native results interpreted |
| --- | --- |
| OpenClaw | `before_tool_call` and `before_message_write`: `block` and `blockReason`; `before_prompt_build` and legacy `before_agent_start`: system prompt and prepend/append context fields; message-sending hooks: `cancel`; `before_agent_finalize`: `action: revise` and `retry.instruction` |
| Hermes | `pre_tool_call`: canonical `action: block` with a nonempty `message`; `pre_llm_call`: string or `context`; `pre_verify`: `action: continue` or `decision: block` with a message/reason prevents finalization |
| OpenCode v2 | `permission.evaluate`: changes to `effect: deny`; session context, compaction, generation and title hooks: added or replaced system text parts |

Other successful callbacks are recorded as completed runs without interpreting
their returned data as model context or a blocking decision. Returned-character
counts cover the fields in the table; they do not count diagnostic text, tool
arguments, approval descriptions, or arbitrary messages. Hermes shell hooks
must pass through Hermes's response normalization before forwarding. Plain
whitespace context strings are ignored by Hermes, while nonempty dictionary
context strings retain their original characters.

OpenCode requires `"protocol": "opencode-v2"` and snapshots taken immediately
before and after each callback. Put the before projection in `before` and the
after projection in `result`. For permissions include `effect` and optional
`message`. For session context include `system`, an array of native
`{"type":"text","text":"..."}` parts. Deep-copy the before snapshot: keeping a
reference to the mutable event loses the original state. An unchanged denial
from a previous handler does not count as a new denial. Unchanged or reordered
system parts do not count as new text; added/replaced parts contribute their
full Unicode character counts, including additional copies of an existing part.
Missing snapshots and unsupported protocols are rejected. OpenCode v1's plugin
API is not interpreted by this adapter.

These commands do not install plugins, intercept another host, or subscribe to
all callbacks through an ordinary observer hook. The host must forward each
handler it actually observes. A configured handler that did not execute, an
aggregate dispatcher return, or a `tool_completed` event is not a completion.

Native result definitions: [OpenClaw plugin hook types](https://github.com/openclaw/openclaw/blob/main/src/plugins/hook-types.ts),
[Hermes plugin directives](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/plugins.py),
[OpenCode v2 session hooks](https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/effect/session.ts)
and [permission hooks](https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/effect/permission.ts).

## Shared adapter contract

The shared contract for every harness is `hookrun.Record` in `daemon/hookrun`.
Host adapters implement `hookrun.Decoder`: one input message produces a record,
a recognition boolean and an error. The shared package owns record validation
and execution ID construction, without importing native harness adapters.

Codex's `codex.Decoder` lives in `daemon/hookrun/codex` and implements that shared
interface. It owns notification parsing and native outcome mapping. The CLI
selects the adapter through `hookrun.Decoder`; collection, session attribution,
storage and rendering consume the shared record. Claude's transcript parser
uses the same record-to-event conversion. Additional native adapters follow
this dependency direction and keep their protocols out of the shared package.

Hosts that already normalize events can use `secure-agent hooks record --format
record` and send the versioned contract directly:

```json
{
  "type": "hook_run",
  "version": 1,
  "harness": "codex",
  "session_id": "thread-uuid",
  "run_id": "codex:completion-uuid",
  "ts": "2026-10-13T09:00:01Z",
  "event": "PreToolUse",
  "status": "ok",
  "duration_ms": 12,
  "chars": 0
}
```

`script` is optional. Identifiers contain only letters, digits, dots, underscores,
colons and hyphens, with a maximum of 256 characters. Event labels are bounded
to 128 characters; script labels additionally exclude colons. Counts must be
nonnegative. Supported outcomes are `ok`, `inject`, `deny`, `block`, `error` and
`cancelled`. Versions 1 and 2 are accepted; unknown fields and other versions are rejected. The supported harness
names are `claude`, `codex`, `openclaw`, `hermes` and `opencode`; accepting a name
in this contract does not supply a native adapter for that harness.

### Version 2 evidence metadata

Version 1 remains supported. To provide attributable findings, hosts sending
normalized records use version 2 and an `evidence` object:

```json
{
  "type": "hook_run",
  "version": 2,
  "harness": "hermes",
  "session_id": "session-uuid",
  "run_id": "hermes:completion-uuid",
  "ts": "2026-10-13T09:00:01Z",
  "event": "pre_tool_call",
  "script": "policy.py",
  "status": "error",
  "duration_ms": 2000,
  "chars": 0,
  "evidence": {
    "handler_id": "handler-uuid",
    "config_id": "revision-uuid",
    "operation_id": "action-uuid",
    "execution_mode": "foreground",
    "reason_code": "timeout",
    "control_role": "security",
    "action_outcome": "stopped",
    "duration_known": true,
    "chars_known": false
  }
}
```

`handler_id` identifies a registered handler across invocations; `config_id`
changes when that handler's configuration changes. `operation_id` identifies
one attempted action, not a turn containing several different actions. These
are opaque host inventory tokens, never commands, paths, arguments or output.
Do not derive handler identity from a script basename. These fields use the
same bounded identifier syntax as record IDs.

`execution_mode` is `foreground` or `background`; omit it when unknown.
`control_role` is `security` or `other`; `action_outcome` is `stopped` or
`proceeded`. Both describe observed host facts, not conclusions inferred from
the callback status. `reason_code` accepts `timeout`, `dependency-unavailable`,
`invalid-output`, `permission-denied`, `execution-failed` or `policy-block`.
Do not include diagnostic text. Omitted fields remain unknown.

`duration_known` and `chars_known` distinguish measured zero from unknown.
Optional `context_chars` counts only model context contributed by this handler,
excluding decision feedback and diagnostics; omit it when not measured. Legacy
positive counts remain visible, but legacy zeros cannot prove a measurement.

OpenClaw, Hermes and OpenCode forwarding envelopes also accept version 2 with
`evidence`. Codex wrappers accept the same optional `evidence` object alongside
`id` and `notification`. Native adapters derive measurement availability and
recognized context counts from their native inputs. Codex derives opaque
handler identity from its native `run.id`; the other native adapters require
host inventory IDs. Configuration revisions and execution mode remain
host-supplied. Claude transcript records currently lack stable
registered-handler identity and therefore remain history totals.

Storage deduplicates on session ID and run ID. Completions stay outside the
general event timeline and retain the existing history retention and row budget.
Forward only completions actually observed. Do not infer executions from hook
configuration, tool activity, or an observer callback that cannot see other
handlers' results. Native result adapters require host instrumentation at the
individual handler boundary.

Protocol sources: [Codex hook notifications](https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/hook.rs)
and [rollout persistence policy](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs).
