# Hook history

[Documentation](README.md) · [Session workflows](USAGE.md)

The session Hooks view summarizes recorded completions: runs, failures, blocks,
returned characters and time. Claude Code completions come from transcripts.
Codex completions come from an existing host forwarding app-server notifications.
An empty history does not establish that no hooks ran.

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
configured handler, repeats between executions and can include a source path;
it is unsuitable as a completion ID and is not stored.

Completion notifications do not identify the executed command. If the host has
a trusted mapping from its hook inventory, it may include an optional envelope
`script`, such as `guard.py`. Only a basename is accepted. Without it the console
shows **not recorded** and combines runs with the same event and missing script.
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
`cancelled`. Unknown fields and versions are rejected. The supported harness
names are `claude`, `codex`, `openclaw`, `hermes` and `opencode`; accepting a name
in this contract does not supply a native adapter for that harness.

Storage deduplicates on session ID and run ID. Completions stay outside the
general event timeline and retain the existing history retention and row budget.
Forward only completions actually observed. Do not infer executions from hook
configuration, tool activity, or an observer callback that cannot see other
handlers' results. OpenClaw, Hermes and OpenCode need host instrumentation or
native completion evidence before their adapters can report hook executions.

Protocol sources: [Codex hook notifications](https://github.com/openai/codex/blob/main/codex-rs/app-server-protocol/src/protocol/v2/hook.rs)
and [rollout persistence policy](https://github.com/openai/codex/blob/main/codex-rs/rollout/src/policy.rs).
