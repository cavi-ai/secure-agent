# Your first observed session

[Documentation](README.md) · [Getting started](GETTING_STARTED.md)

Use this walkthrough after installing Secure Agent and choosing a harness in Setup. You will identify one session, inspect its evidence and export a report. It does not require real secrets, firewall blocking or automatic resource interventions.

## 1. Check the monitor

Keep Secure Agent running. Open **Setup & Permissions…** and refresh your selected harness's result. For Claude Code or Cursor, install the selected hooks and run the installed-hook check. A passing check confirms a daemon round trip; live activity is checked in the next steps.

If you enabled the CLI under Optional capabilities, run:

```bash
secure-agent status
secure-agent doctor
```

Expect status to report a running daemon. Doctor can report failures for an enabled capability that needs attention; read its individual checks and suggested fixes. If the daemon is unavailable, launch the installed app before continuing. See [Troubleshooting](TROUBLESHOOTING.md).

## 2. Start a small task

Open the selected harness in a project you recognize. Ask it to list the project's files and summarize its README, without changing files or contacting external services. Use a disposable project if you prefer. Keep the session open while checking the results.

Open **Open console** from the menu bar, then inspect Sessions. Find the session using its harness, workspace and start time. In Setup, refresh **Observed session coverage** for the running session.

| Signal | What to look for | What the result establishes |
|---|---|---|
| Session identity | Matching harness, workspace and start time | The monitor attributed a process family to this session |
| Recorded activity | Tool or trace entries from this task, when the harness supports them | Those entries reached a supported collector |
| Guarding | An observed guard invocation for a supported hook | That invocation reached the guard; a setup probe alone does not establish this |
| Payload inspection | An attributed observation, when available | Only the observed routed traffic; a machine-level hit may lack session identity |

An unsupported capability is expected for some harnesses. `not-observed`, `unattributed` and `stale` do not establish coverage. Use [Coverage and evidence](CONCEPTS.md) to interpret the states before changing settings.

## 3. Read and export the report

Open the session in the console. Compare the task with its recorded tools, files, hosts and findings. Depending on the harness and optional telemetry, some sections can be empty. An empty findings list means no findings were recorded; it does not establish that every operation was inspected.

Use the session's export controls to save its report. With the CLI, list sessions, then replace `SESSION_ID` below with the matching session's ID or unique prefix:

```bash
secure-agent sessions
secure-agent session SESSION_ID
secure-agent session SESSION_ID --json
```

The first report is Markdown; `--json` returns the structured report. See [Session history](USAGE.md#inspect-session-history) for report contents and filtering.

## 4. Choose the next capability

Once you can find and inspect your session, enable one capability at a time and recheck its result:

- [File telemetry](GETTING_STARTED.md#enable-file-telemetry) adds system file observations on macOS.
- [File and egress protection](PROTECTION.md) explains guard prompts, secret fingerprints and traffic inspection, including their limits.
- [Resource controls](USAGE.md#manage-session-resources) explains observation and opt-in interventions.
- [Local chat](SYSTEM_AGENT.md) adds local analysis and explicitly confirmed actions.

Finish the harness session normally. Quitting Secure Agent stops its child daemon; the optional headless service has a separate lifecycle described in [Getting started](GETTING_STARTED.md#linux-and-headless-nodes).
