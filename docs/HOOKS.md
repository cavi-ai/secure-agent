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
