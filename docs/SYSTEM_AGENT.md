# System Agent — Local Chat, Plans and Harness Dispatch

The system agent is the console's **Agent** tab: a chat with a model served by
your own Ollama. It answers questions, drafts work for a coding agent (a
"harness": Claude Code, Codex, OpenClaw or Hermes Agent) and hands that work to
the harness **running against the same local Ollama**. Sensitive work — SSH
keys, Git credentials, commit signing, a harness's sign-in and config — gets
done without a prompt, file or answer reaching a vendor model.

It is opt-in, and every run is started by you: the model proposes, you
dispatch.

## Turn it on

1. Serve a model with Ollama and pull what you want to use:

   ```bash
   ollama pull qwen3          # chat model
   ollama pull qwen3-coder    # a tool-calling model for dispatched harnesses
   OLLAMA_CONTEXT_LENGTH=64000 ollama serve   # agents need a long context; Hermes refuses less than 64k
   ```

2. Enable it in `~/.config/secure-agent/config.yaml` (applied live, no restart):

   ```yaml
   system_agent:
     enabled: true
     endpoint: "http://127.0.0.1:11434"   # Ollama; must be loopback
     model: qwen3                         # chat model ("" = the first model Ollama lists)
     harness_model: qwen3-coder           # model dispatched harnesses run ("" = model)
     timeout_minutes: 30                  # bound on one headless run (up to 240; 0 = 30)
   ```

3. Open the console's **Agent** tab. The header shows the chat model and the
   Ollama version; **Harnesses & skills** shows which harnesses can run now
   and why the others cannot.

## How it works

1. **Chat.** You write a message and pick where it is routed (**Route to**:
   Claude Code, Codex, OpenClaw, Hermes Agent) and, optionally, the folder the
   work happens in. Your message is masked (below) and stored; the model's
   reply lands a moment later.
2. **Skills.** Seven procedures ship inside the daemon: `ssh`, `git`,
   `signing`, `claude`, `codex`, `openclaw`, `hermes` — creating and loading
   keys, keychain credential helpers, SSH/GPG signing, and each harness's
   sign-in, config and local-model setup. The chat model gets the ones your
   request touches (up to three, by keyword); a dispatched harness gets the
   ones its plan names, appended to its task. Click a skill to read it.
3. **Proposal.** When you ask for something to be done, the reply ends with a
   proposal: a title, the harness, a mode, the folder, steps, and the exact
   task the harness will receive. The harness you picked in **Route to** wins
   over the model's choice; a mode the model got wrong becomes `terminal`.
4. **Plan.** Save the proposal as a plan, or dispatch it directly (it is saved
   first). When the proposal's harness cannot run now — not installed, Ollama
   down, Ollama too old, model not pulled — the daemon **saves it as a plan on
   its own**, with the reason. **Save as plan** in the composer turns any
   request into a plan without asking the model, which also works while the
   model is down.
5. **Dispatch.** Each plan has **Run headless** and **Open in terminal**,
   enabled only while its harness can run. Nothing dispatches by itself; a
   saved plan waits for your click.

### Dispatch modes

| Mode | What happens | Use it for |
|---|---|---|
| **Headless** | The daemon runs the harness non-interactively in the plan's folder (never `/`), one run at a time, bounded by `timeout_minutes`, in its own process group. The answer, masked, shows under **Runs**. | Edits: harness config, dotfiles in a folder, repository changes. |
| **Terminal** | The daemon writes a one-shot script (0700, deletes itself when it starts) and opens it in Terminal (macOS). The harness starts interactively with the task as its first message; you approve each step. Off macOS the run shows `sh '<script>'` to copy. | Anything that needs you at the keyboard: passphrases, browser or device-code logins, hardware keys. |

### How each harness is pointed at Ollama

No recipe bypasses a harness's approvals or sandbox, and your own hooks
(secure-agent's guard included) stay on.

| Harness | Model routing | Headless | Terminal |
|---|---|---|---|
| Claude Code (`claude`, Ollama ≥ 0.14) | `ANTHROPIC_BASE_URL=<endpoint>`, `ANTHROPIC_AUTH_TOKEN=ollama`, `ANTHROPIC_API_KEY=""`, every model slot set to the harness model; the same environment is passed with `--settings` so a user settings file cannot route it elsewhere. `CLAUDE_CODE_OAUTH_TOKEN` and the Bedrock/Vertex/Foundry switches are removed. Non-essential traffic, telemetry, error reporting and auto-update are off; `WebFetch` and `WebSearch` are disallowed. | `-p <task> --permission-mode acceptEdits --output-format json`: edits in the folder, other shell commands denied. | `claude … <task>` with its default permission prompts. |
| Codex (`codex`, Ollama ≥ 0.13.4) | `--oss --local-provider ollama -m <model>`, `CODEX_OSS_BASE_URL=<endpoint>/v1`. | `exec … --sandbox workspace-write --skip-git-repo-check`: edits inside the folder, no network. | `… --sandbox workspace-write --ask-for-approval on-request <task>`. |
| OpenClaw (`openclaw`) | A config written by secure-agent (`OPENCLAW_CONFIG_PATH`, 0600, removed after the run) whose only provider is the local Ollama (native API, no `/v1`) and whose primary model is `ollama/<model>`; update checks and Bonjour off. | `agent exec <task> --model ollama/<model> --cwd <folder> --timeout <s>` with `tools.exec.mode: deny`: file tools scoped to the folder, no host commands. | `chat --message <task>` with `tools.exec.mode: ask`. |
| Hermes Agent (`hermes`) | `--provider custom -m <model>` with `CUSTOM_BASE_URL=<endpoint>/v1`; `HERMES_YOLO_MODE` removed. | `-z <task>` with `HERMES_WRITE_SAFE_ROOT=<folder>`; one-shot runs deny dangerous commands. | `chat --provider custom -m <model> -q <task>`. |

Every recipe also sets `NO_PROXY=127.0.0.1,localhost,::1` (your own entries
kept after them) so a proxy in the daemon's environment never carries the
model traffic. A run's **Command** shows the environment and command line
exactly as they ran, with the task shown as `<task>`.

## Guarantees (enforced, not promised)

| Guarantee | Enforcement |
|---|---|
| **Loopback only** | Config validation rejects a non-loopback `system_agent.endpoint` when enabled; the agent re-checks and reads as off otherwise. Every harness recipe points the harness at that endpoint. |
| **Agents cannot drive it** | `/agent/*` are NoAgent routes: refused to agent processes on the unix socket and, on the console listener, to any TCP client inside an agent family (see [API.md](API.md#-peer-authentication--endpoint-roles)). A harness cannot chat with the system agent, save a plan or dispatch one. |
| **The model proposes, you dispose** | A reply can only carry a proposal. Chat, plan save and dispatch are separate requests; dispatch is a pinned-UI mutation and the console confirms each one. A plan never dispatches itself. |
| **Secrets never persist or reach the model** | Every message, plan title, task and step is masked with the firewall's typed patterns and registered fingerprints (`[REDACTED:<rule>]`) before it is stored or sent. A text whose secret survives masking (e.g. only present encoded) is refused with `422`. Replies and run output are masked the same way before they are stored. |
| **Harness safety stays on** | No recipe passes `--dangerously-skip-permissions`, `bypassPermissions`, `--dangerously-bypass-approvals-and-sandbox`, `danger-full-access`, `--yolo` or `tools.exec.mode: full` (a test checks every recipe). |
| **Bounded** | One headless run at a time, `timeout_minutes` per run, output capped at 1 MB in memory and its last 60 lines stored. The chat answers one message at a time; the conversation keeps 500 messages, plans 500, runs 1000. |
| **Audited** | Each dispatch and plan deletion lands in the policy audit (`sysagent-dispatch`, `sysagent-plan-delete`) with the plan, harness, mode, model and folder. |

## What the model sees

- The system prompt: its role, the reply format, each harness's state (ready,
  or why not), the harness and folder you picked, every skill's one-line
  summary and the full text of up to three skills your request touches.
- The last 20 messages of the conversation, masked, with earlier proposals as
  their JSON blocks.

Never a secret value, never file contents. The model has no tools: it cannot
read files or run commands.

## Known limits

1. **A small local model is not a careful engineer.** Read the proposal's
   task before you dispatch it; that text is exactly what the harness gets.
2. **Headless runs still act.** Codex and Claude Code edit files in the
   folder; Codex runs sandboxed commands; Hermes runs commands its one-shot
   policy does not call dangerous. Pick the folder deliberately, and use
   terminal mode when in doubt.
3. **Harness CLIs move fast.** The recipes match Claude Code, Codex, OpenClaw
   (`agent exec`) and Hermes Agent (`-z`, `--provider custom`) as of
   September 2026. An older release that lacks a flag fails the run with its
   own error, shown under **Runs**.
4. **A headless run outlives a stopped daemon.** It runs in its own process
   group; its outcome is not recorded, and the next start marks the run and
   its plan `failed`.
5. **The console tab needs macOS.** Off macOS the console listener cannot
   identify its TCP client, so it refuses `/agent/*` like every NoAgent route;
   the unix socket still serves them to the owner.
6. **OpenClaw runs use secure-agent's config**, not yours: channels, plugins
   and other providers in `~/.openclaw/openclaw.json` are not loaded for a
   dispatched run.
