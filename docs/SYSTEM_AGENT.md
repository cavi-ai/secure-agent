# Secure Agent — Local Ollama Chat and Confirmed Actions

The console's **Agent** tab chats directly with a model on your own Ollama.
For local work, the model may propose one exact shell command, folder and mode.
The daemon stores that proposal as data; you review and confirm it before it
runs. An SSH key can be generated this way in Terminal, where `ssh-keygen`
prompts for its passphrase without putting the passphrase in chat.

**Harness handoff** is a separate, optional section for Claude Code, Codex,
OpenClaw, Hermes Agent and Pi runner. Saving a handoff plan does not route chat
or start a harness. A second confirmation dispatches a plan. Both the chat
model and dispatched harness models use the configured loopback Ollama.

## Turn it on

1. Start Ollama and pull a chat-capable model, for example `ollama pull qwen3`.
   A tool-calling model such as `qwen3-coder` can be selected separately for
   optional harness handoffs.
2. In the menu bar app, choose **Settings → Secure Agent** and enable
   **Chat → Enable chat**. **Ask Agent** opens the console. For a headless install or
   specific models, use `~/.config/secure-agent/config.yaml`:

   ```yaml
   system_agent:
     enabled: true
     endpoint: "http://127.0.0.1:11434" # loopback only
     model: ""                         # first chat-capable model, or pin one
     harness_model: ""                 # defaults to the chat model
     timeout_minutes: 30               # headless command/run limit
   ```

The Agent header names the active chat model and Ollama version. The chat
composer says **Local Ollama · no harness**. Chat occupies the main surface;
**Review queue**, **History**, and **Tools** open a single side panel. On narrow
screens the panel replaces the conversation until closed, preserving your draft.
Quick commands such as **Check SSH** and **Check Git signing** prepare editable
prompts without sending them or running a command. **Working folder** expands
the optional folder field. **History** holds recent runs and saved plans; run
output expands on demand. **Tools → Harness handoff** has its own task, harness
and folder fields. Security alerts remain visible in a compact banner with a
**Review alerts** link back to Home.

## Security action queue

In **Security flags**, open **Individual flags** and select a row to inspect
its recorded evidence, session, process, advisor verdict, and rule playbook in
the sidebar. **Ask the advisor for a plan** uses that flag's stored context;
the resulting advice and supported actions appear in the same sidebar.

On the **Agent** page, **Analyze activity** sends a bounded, masked
summary of recent stored flags, evidence, and operator/control actions to the
same local Ollama chat model. The daemon builds the summary; the browser does
not provide findings or commands. The model returns an advisory response and
may propose one exact local command. Each response is kept in the **Security
action queue** with links back to its source flags. Analysis alone never runs
the command and never dispatches a harness. The operator may:

- **Review and run locally:** see the exact command and folder in a separate
  confirmation, then execute it once through `/agent/actions`.
- **Save plan:** choose a harness and folder and save the recommendation as a
  Terminal handoff plan. Saving does not dispatch it; a later dispatch needs
  its own confirmation.
- **Dismiss:** remove a pending recommendation from the queue. A saved or
  dismissed recommendation cannot later be run as a local command.

Clearing the conversation leaves analysis recommendations and saved plans in
place. Pending recommendations survive the rolling chat history, with at most
100 pending items; saved plans have their own storage. The analysis uses
existing evidence, event, and audit records, so no new background collection
or alert stream is required.

## Local chat and commands

1. Send a message to Ollama. You may name the folder for a possible command.
   Chat rejects a `harness` field from older clients, so a chat send cannot
   silently become a handoff.
2. The model answers or includes one `local-command` block with `command`,
   `mode` (`headless` or `terminal`) and `workdir`. A malformed or multiple
   block is shown as text and cannot be run. It is never auto-executed.
3. **Review and run** displays the exact command, folder and mode, and warns
   that shell commands have your account's file and network access. After
   confirmation, the browser sends only the assistant message ID to
   `POST /agent/actions`. The server runs only that stored command, once;
   callers cannot substitute a command or folder in the execution request.

Headless commands run through `/bin/sh -c` in the chosen folder with a minimal
environment and the configured timeout. Their masked output appears under
**Runs**. They cannot use `/` as the working folder. Terminal commands use an
owner-only one-shot script that removes itself when launched. Terminal mode is
for passphrases, hardware keys, login and other interactive work. An **opened**
status means Terminal opened; it does not prove the command succeeded.

Seven built-in procedures (`ssh`, `git`, `signing`, `claude`, `codex`,
`openclaw`, `hermes`) guide the model. The chat receives up to three relevant
procedures selected by keyword. Click a skill in the console to read it.
Commands and answers are masked by the firewall before storage or display;
unmaskable secrets are refused.

Private-key envelopes are masked in full, including their contents. Headless
stdout, stderr, and answer files are bounded to 1 MiB each. Oversized captures
are withheld because truncation can remove the context needed for safe masking;
the retained tail is selected only after masking the complete bounded output.
Chat fails if its message cannot be stored. Harness dispatch records its run
and plan before starting a process or opening Terminal; a failed write stops
execution. A durable local-command claim cannot be reopened by a concurrent
chat or saved-plan update.

## Temporary task files

Every local command and harness dispatch gets a private, owner-only task
workspace. Launch scripts, per-run harness configurations, and answer files
live there. `TMPDIR` points to the same workspace, so tools that honor it
keep their temporary files there too.

Headless runs remove the workspace on completion, failure, or timeout.
Terminal scripts install cleanup before changing folders or launching the
command: success, failure, and handled HUP/INT/TERM signals all remove the
workspace, including files the harness created inside it. The launch script
also removes itself as soon as it starts.

After a crash or forced kill, startup removes orphaned task workspaces. A
live Terminal shell keeps its workspace even if the daemon restarts. A
pending, unopened script expires once its creator has exited and startup
reclaims it; dispatch again rather than reusing an old manual command.

Cleanup preserves generated SSH keys, requested outputs in the working
folder, saved plans, and redacted chat/run history. Files a command or harness
writes outside its task workspace are outside this cleanup. This is ordinary
filesystem deletion, not encryption or guaranteed forensic erasure; a forced
kill can leave temporary data until the next startup. Stored chat and run
history are redacted, but are not encrypted by this feature.

## Optional harness handoff

Write a separate task, choose a harness and folder, then **Save handoff plan**.
The plan waits for **Run headless** or **Open in terminal** and a dispatch
confirmation. A harness that is unavailable stays in Plans with its reason.
Previously saved model proposals remain visible for compatibility. The
`system_agent.harness_model` selects the Ollama model for handoff; no chat
message is passed to a harness unless you explicitly place its content into
a handoff plan.

| Harness | Local model route | Run restriction |
|---|---|---|
| Claude Code | Anthropic-compatible Ollama endpoint with model slots pinned, web tools and nonessential traffic disabled | Headless edits or interactive Terminal, with its permissions active. |
| Codex | `--oss --local-provider ollama` and local `/v1` endpoint | Headless in workspace-write sandbox or interactive Terminal. |
| OpenClaw | Per-run config with only the local Ollama provider | Host commands denied headless, asked in Terminal. |
| Hermes Agent | Custom provider at local `/v1` endpoint | Write-safe root set for headless runs. |
| Pi runner | Per-run isolated `models.json` with only local Ollama; offline startup and telemetry disabled | **Terminal only.** Pi has no built-in sandbox. Extensions, context files, project trust, shell tool and session persistence are disabled. Its file tools can still access any file your account can. |

Each recipe bypasses proxy variables for loopback and avoids flags that disable
the harness's own approval or sandbox settings. Headless harness runs are
limited to one at a time with a timeout; a Terminal handoff is interactive.
Inspect the plan's task and folder before dispatching it.

## Security boundary and limits

- The endpoint is accepted only on loopback. The HTTP client refuses
  redirects, so a local server cannot forward a chat prompt by redirect.
- `/agent/*` are NoAgent routes: agent processes cannot chat, confirm a local
  command, save plans or dispatch harnesses through the daemon. Mutations
  require the pinned console UI path.
- A confirmed arbitrary shell command runs as your account. Confirmation is
  a review gate, **not a sandbox**. It can read/write files and use the
  network. The daemon removes inherited environment variables before a
  headless local command, but files accessible to the account remain so.
- The model itself has no file or shell tools. It sees the system prompt,
  relevant skill text and the last 20 masked conversation messages. Local
  command output and harness plans are not fed back as model instructions.
- Commands can start once per proposal. Headless output is bounded and
  masked before storage. Local actions, handoff dispatches and plan deletions
  are recorded in the policy audit without command output or secret values.
- Pi's project-trust feature is not a sandbox. Terminal-only handoff and its
  disabled shell tool reduce risk but do not confine its read/write tools to
  the chosen folder. Use the direct local command path for sensitive work.

### Review a selected security finding

**Send to local agent review** on a finding or pattern submits the selected flag IDs to local Ollama. The daemon builds a bounded, masked summary of recorded file, process, timestamp, destination, and credential-owner metadata. It does not read the `.env` contents into the chat. **Inspect file details** shows variable names only for supported small `.env` files; values and ambiguous multiline content are withheld. The recommendation appears in the Agent review queue and links back to the finding. Review and run locally requires a separate command confirmation; save a plan for later delegation to a harness when needed.

For a suspected stale `.env`, inspect variable names and consumer references without printing values before approving removal. Ordinary startup reads and cloud/CDN traffic are correlations, not proof that secret bytes left the machine.
