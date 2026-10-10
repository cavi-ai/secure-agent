# Troubleshooting

[Documentation](README.md) · [Getting started](GETTING_STARTED.md)

Start with **Run Doctor…** in the menu bar or **Run Doctor** on the File Telemetry card. If the CLI is installed, `secure-agent doctor --json` provides the structured checks. A running daemon establishes availability; use the named capability checks to diagnose missing coverage.

## The daemon is unavailable

Launch `/Applications/Secure Agent.app` and retry `secure-agent status`. The normal app owns its child daemon, so quitting the app stops it. On a headless node, check `secure-agent service status` instead. Run either the app or the optional service against a store, not both. For source builds, see [Development](DEVELOPMENT.md).

## The menu bar icon is missing

Open Secure Agent from the Dock to reach Settings. Allow it under **System Settings → Menu Bar**. On macOS Tahoe, Control Center can associate the status item with its launcher; the launcher's Menu Bar permission may also need enabling. The detailed [setup troubleshooting](GETTING_STARTED.md#troubleshooting) explains this behavior. Reinstalling is not a substitute for the permission.

## File Telemetry is not green

Run Doctor from **Settings → Telemetry**. Follow its named fixes for registration, **Login Items & Extensions** and **Full Disk Access**, then refresh. Use the installed `/Applications` copy, because helper registration belongs to that copy. `secure-agent telemetry repair` requests re-registration through the running menu bar app and fails unless the helper runs within 60 seconds. See [Enable file telemetry](GETTING_STARTED.md#enable-file-telemetry).

## A hook check passes but the session has no coverage

Start the selected harness and run the small task in [Your first observed session](FIRST_SESSION.md). Refresh the live session's observed coverage. Confirm the harness supports the capability in the [collector table](ARCHITECTURE.md#collectors). For a failed installed-hook check, verify Python 3.10+ is available, reinstall the selected hooks through Setup and rerun the check. Development symlinks alone do not register hooks.

## The console cannot read telemetry

Use **Open console** from the menu bar so it receives the console credential. Confirm the proxy listener is enabled. Opening the static dashboard without its credential can show assets while API requests fail. The proxy token and console token serve different purposes; see [Console access](API.md#console-access-on-the-proxy-port). Keep credentials out of reports and logs.

## Claude Code cannot connect after routing is enabled

Start Secure Agent before launching the routed harness. If you want to stop routing, turn it off in **Settings → Secure Agent → Traffic**, then retry. Inspection requires the configured route and CA trust; tunnel mode does not decrypt payloads. See [Proxy routing](CONFIGURATION.md#routing-modes).

## A report or source shows stale data

Retry the named failed source. Secure Agent retains last-known data after some read failures and marks it stale; that data is not a fresh result. Session-list query failures can return HTTP 503 rather than an empty list. Compare the refreshed evidence and its timestamp before relying on it. See [Coverage states](CONCEPTS.md#interpret-coverage-states) and [API](API.md).

## Local analysis is unavailable

Check the configured loopback model server and model, then the Agent page's retry state. Detection and enforcement continue independently of the advisor. See [Local chat](SYSTEM_AGENT.md) and the [advisor configuration](CONFIGURATION.md#advisor-map).

## A fleet read request returns 401

Send the collector's configured read token as a bearer credential. Enrollment secrets sign node events; they are not collector read tokens. Keep a remote collector behind TLS, and configure read authentication before exposing it beyond loopback. See [Fleet](FLEET.md).

## Report a reproducible issue

Include the installed version or source commit, macOS/Linux version, harness, failing Doctor check and the smallest reproduction. Remove credentials, private paths and sensitive payloads from reports. Use the [security policy](../SECURITY.md) for vulnerability reports.
