# Getting started

[Documentation](README.md) · [Project home](../README.md)

Secure Agent monitors local AI-agent sessions, reports security findings and resource use, and offers optional file guards and outbound payload inspection.

This documentation follows the current `main` checkout. A downloaded release can have an earlier setup flow or fewer capabilities; use its release notes to identify what it includes.

## Install on macOS

You need **macOS 14 or newer**. The packaged app includes the daemon, CLI and hook scripts; you do not need Go or Xcode to run it. Python 3.10 or newer is needed for the Python harness hooks.

1. Open the [latest release](https://github.com/cavi-ai/secure-agent/releases/latest) and download `SecureAgent-<version>.dmg`.
2. Open the DMG and drag **Secure Agent.app** to **Applications**.
3. Launch `/Applications/Secure Agent.app`. Keep that installed copy as the one you run: file-telemetry registration belongs to it.

To build the current checkout instead, follow [Development](DEVELOPMENT.md#build-and-install).

## Set up your first agent

1. **Choose** — select a harness and see guarding, recorded activity, and payload inspection as separate capabilities. The bundled daemon starts and stops with the app.
2. **Enable** — explicitly install hooks for Claude Code or Cursor alone, preserving existing user hooks. Other harnesses can continue with their observation path. Hook scripts require Python 3.10 or newer; installing hooks does not install Python.
3. **Result** — run an inert installed-hook check or view the result without a check. The check verifies the hook's daemon round trip; it does not establish that a running agent invokes the hook or that its traffic is inspected. Configuration changes and unavailable status require another check or refresh.

File telemetry, additional hook scripts, traffic routing, secret registration, guard rules, the local advisor, Open at Login, and CLI installation remain under **Optional capabilities** after the result and in Settings. New first-use setup leaves file-telemetry registration and permission panes deferred until you explicitly enable that capability.

Everything is also manageable later from the menu bar icon (**Setup & Permissions…**, **Settings…**, **Uninstall…**, **Open console**, **Ask Agent**). Secure Agent appears in the Dock, opens the setup flow on first use, and opens Settings on subsequent launches. Click the Dock icon to reopen Settings after closing its window; quit the app to stop its child daemon.



Saved Secure Agent preferences and monitoring data remain in their existing locations across updates. Allow **Secure Agent** in System Settings → Menu Bar. Review notification, Login Items and Full Disk Access prompts through the native Setup flow.

## Check what is working

Start a session in the selected harness, then recheck **Observed session coverage** in Setup. Guarding, recorded activity and payload inspection have separate results. An absent observation remains unknown; it does not mean that every action was protected or that nothing happened.

Use **Run Doctor…** from the menu bar for diagnostics. If you install the CLI under Optional capabilities, these commands provide the same starting checks:

```bash
secure-agent status
secure-agent doctor
secure-agent sessions
```

Doctor exits with status 1 when a check fails. Read the named check and its suggested fix rather than treating a running daemon as proof of full coverage.

## Choose optional protection

| Goal | Where to start | Default and scope |
|---|---|---|
| Watch system file activity | Enable file telemetry below | Off until enabled on a new setup; observes access, cannot block it |
| Ask before sensitive file tools run | **Guard My Secrets**, then Settings → File Guard | Named guard rules ship in `monitor`; hard denials still apply to credential-printing and guard/harness mutations |
| Inspect outbound request payloads | Settings → Secure Agent → Traffic | Proxy routing and CA trust are separate opt-ins; tunneled traffic is not decrypted |
| Detect your own secret values | **Scan & Register My Secrets** | Stores salted HMAC fingerprints rather than plaintext values |
| Set session resource budgets | Console resource controls | `observe`, with memory and CPU limits disabled |
| Use local chat or advisory analysis | Settings → Secure Agent or Analysis | Both disabled; recommendations do not authorize commands |

See [Protection](PROTECTION.md), [Resources](USAGE.md#manage-session-resources), and [Local chat](SYSTEM_AGENT.md) for the detailed behavior.

## Enable file telemetry

Endpoint Security telemetry via `eslogger` runs in a collector daemon that ships inside the app bundle and is registered with `SMAppService` — no admin password.

- **Enable:** new first-use setup waits for **Enable file telemetry** in Optional capabilities or Settings → Telemetry. After that choice, the app retains its automatic registration and repair path: registration once per launch and permission guidance once per build. Existing installations retain their telemetry choices.
- **Your two switches:** **Secure Agent** in **System Settings → General → Login Items & Extensions**, then **Secure Agent** in **Privacy & Security → Full Disk Access**; the File Telemetry card in **Settings → Telemetry** turns green on its own.
- **Doctor:** **Run Doctor…** in the menu bar menu, or **Run Doctor** on the card, checks signing, the service in the bundle, registration, Login Items, the launchd job, Full Disk Access, spool health, an old helper under `/Library`, and the daemon's `/doctor`.
- **Fixes:** each failing check has a Fix button; **Fix all** runs them in check order and waits up to 5 minutes on each System Settings switch.
- **Off:** Remove on the card keeps file telemetry off until Enable.
- **Old helper:** a collector installed by an earlier version under `/Library` is removed from the same card (one admin prompt).

## Updates

The menu bar's **Settings… → Updates** tab offers two channels:

- **Stable** — the latest GitHub release. The app downloads the DMG, verifies
  it against the release's SHA-256 `checksums.txt` **before mounting** (a
  mismatch or a missing checksum is a loud refusal, never a silent install),
  replaces the app bundle in place, and relaunches (the daemon, a child of
  the app, comes down and back up with it).
- **Nightly** — builds from the current `origin/main` of a local checkout via
  `packaging/update_nightly.sh` (fetch → ff-only merge → `make install`).
  Developer-grade: it needs a git checkout and the repo toolchain; stable
  needs neither. The check refuses to move a tree with local-only commits.

## Troubleshooting

| Symptom | Next action |
|---|---|
| Menu bar icon is hidden | Open Secure Agent from the Dock to reach Settings. Allow it under System Settings → Menu Bar. |
| File Telemetry is not green | Run Doctor from Settings → Telemetry. Complete the named Login Items or Full Disk Access check, then refresh. |
| Installed hook check fails | Recheck Monitor, verify Python is available, and reinstall the selected harness's hooks through Setup. Check again after configuration changes. |
| Agent session has no observed coverage | Start that harness and refresh. Support and a manual hook check are separate from observed session activity. |
| Console cannot read telemetry | Open it through **Open console**, which passes the console credential. Confirm the proxy listener is enabled. |
| Routed Claude Code cannot connect | Start Secure Agent before Claude Code, or turn routing off in Settings → Secure Agent → Traffic before retrying. |
| Data shows a stale warning | Retry the failed source. Last-known data is retained until a successful refresh; it is not current evidence. |
| Advisor is unavailable | Check the configured loopback model server and the Agent page's retry state. Detection and enforcement continue independently. |

On macOS Tahoe, Control Center can incorrectly associate a status item with the application that launched it. If Secure Agent is allowed but its icon is missing, check **System Settings → Menu Bar → Allow in the Menu Bar** for the launcher as well. Enabling that launcher can restore the shield without restarting the monitor. Reinstalling the app or recreating its status item does not change the launcher's permission. Secure Agent keeps its Dock control available and limits recovery to one attempt for each observed loss of its AppKit item or window.

The CLI's `secure-agent telemetry repair` asks the running menu bar app to re-register its helper and exits 1 unless the helper runs within 60 seconds. Use the installed `/Applications` copy; other copies cannot manage file telemetry.

## Uninstall

Use **Uninstall…** in the menu bar to review removal choices. For source installations and legacy LaunchAgents, binaries and hooks, see `packaging/uninstall.sh` (`make uninstall`). To remove only the optional headless service, use `secure-agent service uninstall`.

## Linux and headless nodes

The Go daemon, CLI and collector build on Linux with `CGO_ENABLED=0`. Linux uses `/proc` for process/network sampling; macOS Endpoint Security, native menu bar setup, DMG installation and telemetry repair are macOS capabilities. Harness hooks and transcript collectors still depend on the harness and its available records. See the [coverage table](ARCHITECTURE.md#collectors).

For a source build on Linux:

```bash
make daemon cli collector
./bin/secure-agentd
```

In another terminal, use `./bin/secure-agent status`. Keep the foreground daemon running while querying it. `make build` also builds the macOS menu bar, so use the named Go targets on Linux.

On macOS, `secure-agent service install` creates a per-user launchd service that starts at login and survives the menu bar app quitting. Run either the app or this service against a store, not both. This is not a system-wide boot service. See [Fleet](FLEET.md) for node enrollment.

Next: [Your first observed session](FIRST_SESSION.md) · [Coverage and evidence](CONCEPTS.md) · [Troubleshooting](TROUBLESHOOTING.md)
