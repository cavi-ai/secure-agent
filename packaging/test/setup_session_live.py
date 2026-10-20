#!/usr/bin/env python3
"""Opt-in macOS fresh-profile Setup → live harness → session console check.

The default path requires an authenticated Codex CLI and graphical login. The
optional Claude path requires a dedicated authenticated config directory.
Codex auth is copied alone to a disposable profile; no prior transcript or user
configuration is imported. No installed app, system permission, or routing is changed.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


REPO = Path(__file__).resolve().parents[2]
TEST = "SetupSessionLiveTests/testFreshProfileToLiveSessionEvidence"


def claude_authentication_status(claude, environment):
    """Return authenticated status without exposing CLI output or credentials."""
    try:
        result = subprocess.run([claude, "auth", "status", "--json"], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    try:
        status = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(status, dict) and status.get("loggedIn") is True


def require_claude_authentication(claude, environment):
    if not claude_authentication_status(claude, environment):
        raise RuntimeError("Existing Claude authentication is unavailable; the Claude live check was not started")


def existing_claude_config_dir(explicit_dir=None, environment=None):
    """Use the existing Claude config without creating or changing one."""
    environment = os.environ if environment is None else environment
    configured = explicit_dir or environment.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude")
    path = Path(configured).expanduser().resolve()
    if not path.is_dir():
        raise RuntimeError("Existing Claude config directory is unavailable; the Claude live check was not started")
    return path


def read_required_output(root, name):
    try:
        return (Path(root) / name).read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"Missing required child output: {name}") from error


def wait_for_path(path, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    while not Path(path).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Timed out waiting for {Path(path).name}")
        time.sleep(interval)


def wait_for_child(process, timeout, label):
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Timed out waiting for {label}") from error


def claude_session_id(path):
    source = Path(path)
    for line in read_required_output(source.parent, source.name).splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("type") == "system" and row.get("subtype") == "init" and row.get("session_id"):
            return str(row["session_id"])
    raise RuntimeError("Claude stream did not report a session identity")


def wait_for_claude_session_id(path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return claude_session_id(path)
        except RuntimeError:
            time.sleep(0.2)
    raise RuntimeError("Timed out waiting for Claude session identity")


def is_valid_claude_session_id(value):
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def attach_claude_transcript(home, claude_config_dir, session_id, timeout=30):
    """Expose only this run's transcript through the daemon's normal glob."""
    if not is_valid_claude_session_id(session_id):
        raise RuntimeError("Claude session identity was not a canonical UUID")
    projects = Path(claude_config_dir) / "projects"
    destination_dir = Path(home) / ".claude" / "projects" / "live-session"
    destination_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    destination = destination_dir / f"{session_id}.jsonl"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = list(projects.glob(f"*/{session_id}.jsonl"))
        if len(matches) > 1:
            raise RuntimeError("Claude session transcript identity was ambiguous")
        if matches:
            destination.symlink_to(matches[0])
            return destination
        time.sleep(0.2)
    raise RuntimeError("Timed out waiting for the isolated Claude session transcript")


def prepare_claude_executable(source, destination, environment):
    """Copy the native CLI so process matching cannot include other Claude runs."""
    source_path = Path(source).resolve()
    destination = Path(destination)
    if not source_path.is_file() or not os.access(source_path, os.X_OK):
        raise RuntimeError("Claude CLI must resolve to an executable native file for isolated process matching")
    try:
        shutil.copy2(source_path, destination)
        result = subprocess.run([str(destination), "--version"], env=environment,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        destination.unlink(missing_ok=True)
        raise RuntimeError("Installed Claude CLI is not a runnable standalone executable; isolated matching is unavailable") from error
    if result.returncode != 0:
        destination.unlink(missing_ok=True)
        raise RuntimeError("Installed Claude CLI is not a runnable standalone executable; isolated matching is unavailable")
    return destination


def verify_denied_stream(stream, denied_result):
    if "deny-once-proof" in stream:
        raise RuntimeError("Claude stream exposed the synthetic denied file contents")
    if not denied_result or not denied_result.get("is_error") or \
            "deny-once-proof" in str(denied_result.get("content", "")):
        raise RuntimeError("Claude did not demonstrate an enforced denied Read result")


def verify_claude_guard_activity(home, session_id):
    activity = Path(home) / ".local/state/secure-agent/activity.jsonl"
    try:
        records = [json.loads(line) for line in activity.read_text(encoding="utf-8").splitlines()]
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Claude guard activity was unavailable or malformed") from error
    observed = {(row.get("tool"), row.get("file_path")) for row in records
                if row.get("session_id") == session_id}
    if ("secret-guard-broker:allow", "guard-allow:env-files") not in observed or \
            ("secret-guard-broker:deny", "guard-deny:env-files") not in observed:
        raise RuntimeError("Claude session did not record both hook-enforced guard decisions")


def verify_cli_reports(cli, ids, foreign_ids, workspace, environment):
    if not isinstance(ids, dict) or not ids or any(not isinstance(value, str) or not value for value in ids.values()):
        raise RuntimeError("Session export identities were unavailable")
    if len(set(ids.values())) != len(ids):
        raise RuntimeError("Harnesses did not produce distinct session identities")
    reports = {}
    for harness, session_id in ids.items():
        try:
            encoded = subprocess.run([cli, "session", session_id, "--json"], env=environment, capture_output=True,
                                     text=True, timeout=20, check=False)
            markdown = subprocess.run([cli, "session", session_id], env=environment, capture_output=True,
                                      text=True, timeout=20, check=False)
        except subprocess.SubprocessError as error:
            raise RuntimeError(f"{harness} session export timed out") from error
        if encoded.returncode != 0 or markdown.returncode != 0:
            raise RuntimeError(f"{harness} session report export failed")
        try:
            report = json.loads(encoded.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"{harness} session JSON export was malformed") from error
        if not isinstance(report, dict):
            raise RuntimeError(f"{harness} session JSON export had an invalid shape")
        session = report.get("session")
        if not isinstance(session, dict):
            raise RuntimeError(f"{harness} session JSON export omitted session identity")
        if session.get("id") != session_id or session.get("harness") != harness or session.get("workspace") != workspace:
            raise RuntimeError(f"{harness} session export identity did not match the selected session")
        lists = ("timeline", "flags", "files", "hosts", "tools", "guard")
        if any(not isinstance(report.get(key, []), list) for key in lists) or \
                not isinstance(report.get("events", 0), int) or not isinstance(report.get("tool_calls", 0), int):
            raise RuntimeError(f"{harness} session report evidence had an invalid shape")
        if (report.get("events", 0) < 0 or report.get("events", 0) > 20_000 or
                report.get("tool_calls", 0) < 1 or len(report.get("timeline", [])) > 500 or
                len(report.get("flags", [])) > 1_000 or len(report.get("files", [])) > 50 or
                len(report.get("hosts", [])) > 50):
            raise RuntimeError(f"{harness} session report evidence exceeded its bounds or omitted tool activity")
        for foreign in foreign_ids:
            if foreign != session_id and (foreign in encoded.stdout or foreign in markdown.stdout):
                raise RuntimeError(f"{harness} session export included another session identity")
        if f"Session `{session_id}`" not in markdown.stdout:
            raise RuntimeError(f"{harness} Markdown export omitted its session identity")
        reports[harness] = report
    if "claude" in reports:
        claude_guard = " ".join(str(row.get("label", "")) for row in reports["claude"].get("guard", [])
                                 if isinstance(row, dict))
        if "allow/once" not in claude_guard or "deny/once" not in claude_guard:
            raise RuntimeError("Claude session report did not retain both guard decision receipts")
        if not any(isinstance(tool, dict) and str(tool.get("key", "")).lower() == "read"
                   for tool in reports["claude"].get("tools", [])):
            raise RuntimeError("Claude session report did not include the observed Read tool evidence")
    return reports


def stop(process):
    if process is None or process.poll() is not None:
        return
    # SwiftPM's XCTest and Codex's tool host create their own process groups.
    # Walk only this child's descendants, rather than relying on killpg.
    rows = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
    parents = [tuple(map(int, line.split())) for line in rows.splitlines()]
    owned = [process.pid]
    for parent in owned:
        owned.extend(pid for pid, ppid in parents if ppid == parent)
    for pid in reversed(owned):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        for pid in reversed(owned):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-claude", action="store_true",
                        help="also exercise an authenticated Claude Code session and its installed guard hook")
    parser.add_argument("--claude-config-dir", type=Path,
                        help="existing Claude config directory (defaults to CLAUDE_CONFIG_DIR or ~/.claude)")
    arguments = parser.parse_args(argv)
    if sys.platform != "darwin":
        raise RuntimeError("This check requires macOS and a graphical login")
    codex = shutil.which("codex")
    claude = shutil.which("claude") if arguments.with_claude else None
    auth = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "auth.json"
    if not codex or not auth.is_file():
        raise RuntimeError("Requires codex on PATH and an authenticated CODEX_HOME/auth.json")
    if arguments.with_claude and not claude:
        raise RuntimeError("--with-claude requires Claude Code on PATH")
    claude_config_path = existing_claude_config_dir(arguments.claude_config_dir) if arguments.with_claude else None
    if claude_config_path is not None:
        try:
            claude_config_path.relative_to(REPO)
        except ValueError:
            pass
        else:
            raise RuntimeError("Keep the Claude config directory outside the repository")

    build = REPO / "dist/setup-session-live"
    build.mkdir(parents=True, exist_ok=True)
    subprocess.run(["go", "build", "-o", str(build / "secure-agentd"),
                    "./daemon/cmd/secure-agentd"], cwd=REPO,
                   env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    subprocess.run(["go", "build", "-o", str(build / "secure-agent"),
                    "./cmd/secure-agent"], cwd=REPO,
                   env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    subprocess.run(["bash", "packaging/swift_macos.sh", "build", "--build-tests",
                    "--package-path", "menubar"], cwd=REPO, check=True)

    daemon = native = harness = None
    # Darwin's sockaddr_un path is limited to 104 bytes. The per-user TMPDIR
    # can already be too long before appending the production socket suffix.
    with tempfile.TemporaryDirectory(prefix="sa-setup-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        home.mkdir(mode=0o700)
        codex_home = home / ".codex"
        codex_home.mkdir(mode=0o700)
        shutil.copyfile(auth, codex_home / "auth.json")
        (codex_home / "auth.json").chmod(0o600)
        # A distinct executable path isolates process matching from other
        # Codex sessions running in the user's graphical login.
        executable = root / ("sacx-" + root.name[-8:])
        shutil.copy2(codex, executable)
        companion = Path(codex).resolve().with_name("codex-code-mode-host")
        if companion.is_file():
            (root / companion.name).symlink_to(companion)
        workspace = root / "project"
        workspace.mkdir()
        (workspace / "README.md").write_text("# Orchard\nA small orchard inventory utility.\n")
        config = root / "config.yaml"
        agent_entries = "  - name: codex\n    match: [" + json.dumps(executable.name) + "]\n"
        isolated_claude = None
        if arguments.with_claude:
            isolated_claude = root / ("sacl-" + root.name[-8:])
            agent_entries += "  - name: claude\n    match: [" + json.dumps(isolated_claude.name) + "]\n"
        config.write_text(
            "agents:\n" + agent_entries +
            "proxy_enabled: true\nproxy_port: 0\nnet_sample_interval_ms: 200\n"
        )
        environment = {key: os.environ[key] for key in ("PATH", "USER", "LOGNAME", "SHELL", "DEVELOPER_DIR")
                       if key in os.environ}
        environment.update({
            "HOME": str(home), "CFFIXED_USER_HOME": str(home),
            "HERMES_HOME": str(home / ".hermes"), "HERMES_STATE_DIR": str(home / ".hermes"), "OPENCLAW_HOME": str(home / ".openclaw"),
            "CODEX_HOME": str(codex_home), "SECURE_AGENT_SETUP_E2E_ROOT": str(root),
        })
        if arguments.with_claude:
            claude_home = home / ".claude"
            claude_home.mkdir(mode=0o700)
            claude_config = str(claude_config_path)
            # The daemon's production collector uses HOME/.claude/projects.
            # A single session-file symlink is added after Claude starts, so
            # existing transcripts in the configured profile are never scanned.
            (claude_home / "projects").mkdir(mode=0o700)
            environment.update({
                "CLAUDE_CONFIG_DIR": claude_config,
                "SECURE_AGENT_SETUP_E2E_WITH_CLAUDE": "1",
                "SECURE_AGENT_SETUP_E2E_HOOKS_DIR": str(REPO / "plugin/hooks"),
            })
            isolated_claude = prepare_claude_executable(claude, isolated_claude, environment)
            (root / "claude-executable").write_text(str(isolated_claude), encoding="utf-8")
            require_claude_authentication(claude, environment)
        try:
            with (root / "daemon.log").open("w") as daemon_log, \
                    (root / "native.log").open("w") as native_log, \
                    (root / "harness.jsonl").open("w") as harness_log, \
                    (root / "harness.stderr").open("w") as harness_errors:
                daemon = subprocess.Popen([str(build / "secure-agentd"), "-config", str(config)],
                                          env=environment, stdout=daemon_log, stderr=daemon_log,
                                          start_new_session=True)
                native = subprocess.Popen(
                    ["bash", str(REPO / "packaging/swift_macos.sh"), "test", "--skip-build",
                     "--package-path", str(REPO / "menubar"), "--filter", TEST],
                    cwd=REPO, env=environment, stdout=native_log, stderr=native_log, start_new_session=True)
                deadline = time.monotonic() + 90
                while not (root / "ready").exists():
                    if daemon.poll() is not None or native.poll() is not None:
                        raise RuntimeError(f"Exited before fresh Setup: daemon={daemon.poll()}, native={native.poll()}; see dist/setup-session-live logs")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Timed out waiting for fresh Setup")
                    time.sleep(0.2)
                prompt = read_required_output(root, "sample-task")
                harness = subprocess.Popen(
                    [str(executable), "exec", "--ignore-user-config", "--ignore-rules",
                     "--skip-git-repo-check", "--sandbox", "read-only", "--json",
                     "-c", 'cli_auth_credentials_store="file"',
                     "-C", str(workspace), prompt +
                     " Use a shell tool to list the files and read README.md." +
                     (" Then wait for a shell sleep of 180 seconds to finish before replying."
                      if arguments.with_claude else
                      " Then wait for a shell sleep of 45 seconds to finish before replying.")],
                    cwd=workspace, env=environment, stdin=subprocess.DEVNULL,
                    stdout=harness_log, stderr=harness_errors, start_new_session=True)
                (root / "harness-started").write_text(str(harness.pid), encoding="utf-8")
                claude_process = None
                claude_stream = None
                claude_errors = None
                if arguments.with_claude:
                    wait_for_path(root / "claude-ready", 150)
                    if harness.poll() is not None:
                        raise RuntimeError("Codex ended before the Claude session could overlap it")
                    allowed = workspace / ".env.allowed"
                    denied = workspace / ".env.denied"
                    allowed.write_text("SAFE_ALLOWED_EVIDENCE=allow-once-proof\n", encoding="utf-8")
                    denied.write_text("SAFE_DENIED_EVIDENCE=deny-once-proof\n", encoding="utf-8")
                    claude_stream = (root / "claude-stream.jsonl").open("w")
                    claude_errors = (root / "claude.stderr").open("w")
                    claude_prompt = (
                        "Use your Read tool to read the file .env.allowed first. Then read .env.denied. "
                        "Report whether each read succeeded or was blocked. Do not modify files."
                    )
                    claude_process = subprocess.Popen(
                        [str(isolated_claude), "--print", "--verbose",
                         "--setting-sources", "project,local",
                         "--settings", str(home / ".claude/settings.json"),
                         "--output-format", "stream-json", claude_prompt],
                        cwd=workspace, env=environment, stdin=subprocess.DEVNULL,
                        stdout=claude_stream, stderr=claude_errors, start_new_session=True)
                    (root / "claude-started").write_text(str(claude_process.pid), encoding="utf-8")
                    if harness.poll() is not None:
                        raise RuntimeError("Codex ended before the Claude process started")
                    stream_session_id = wait_for_claude_session_id(root / "claude-stream.jsonl", 30)
                    attach_claude_transcript(home, claude_config_path, stream_session_id)
                if claude_process is not None:
                    if wait_for_child(claude_process, 360, "live Claude Code session"):
                        raise RuntimeError("Live Claude Code failed; see isolated runner diagnostics")
                    claude_stream.close()
                    claude_errors.close()
                    rows = [json.loads(line) for line in read_required_output(root, "claude-stream.jsonl").splitlines()
                            if line.strip()]
                    read_calls = {block.get("id"): str(block.get("input", {}).get("file_path", ""))
                                  for row in rows if row.get("type") == "assistant"
                                  for block in row.get("message", {}).get("content", [])
                                  if isinstance(block, dict) and block.get("type") == "tool_use"
                                  and block.get("name") == "Read"}
                    tool_results = {block.get("tool_use_id"): block for row in rows if row.get("type") == "user"
                                    for block in row.get("message", {}).get("content", [])
                                    if isinstance(block, dict) and block.get("type") == "tool_result"}
                    allowed_ids = [call for call, path in read_calls.items() if path.endswith("/.env.allowed")]
                    denied_ids = [call for call, path in read_calls.items() if path.endswith("/.env.denied")]
                    allowed_result = next((tool_results.get(call) for call in allowed_ids if call in tool_results), None)
                    denied_result = next((tool_results.get(call) for call in denied_ids if call in tool_results), None)
                    if not allowed_result or "allow-once-proof" not in str(allowed_result.get("content", "")):
                        raise RuntimeError("Claude did not return the allowed synthetic Read result")
                    verify_denied_stream(read_required_output(root, "claude-stream.jsonl"), denied_result)
                    safe_rows = [{key: row.get(key) for key in ("type", "subtype", "session_id") if key in row}
                                 for row in rows]
                    (root / "claude-trace-shapes.json").write_text(json.dumps(safe_rows), encoding="utf-8")
                    (root / "claude-finished").write_text("done", encoding="utf-8")
                result = wait_for_child(native, 360 if arguments.with_claude else 180,
                                        "native Setup/session check")
                sys.stdout.write((root / "native.log").read_text())
                if result:
                    raise RuntimeError("Native Setup/session check failed (see XCTest output)")
                if wait_for_child(harness, 210 if arguments.with_claude else 90, "live harness"):
                    raise RuntimeError("Live harness failed; see dist/setup-session-live/harness.stderr")
                codex_id = next((json.loads(line).get("thread_id") for line in
                                 read_required_output(root, "harness.jsonl").splitlines()
                                 if json.loads(line).get("type") == "thread.started"), None)
                if not codex_id:
                    raise RuntimeError("Codex stream did not report a session identity")
                if arguments.with_claude:
                    claude_id = claude_session_id(root / "claude-stream.jsonl")
                    if codex_id == claude_id:
                        raise RuntimeError("Codex and Claude sessions did not have distinct identities")
                    verify_claude_guard_activity(home, claude_id)
                    ids = {"codex": codex_id, "claude": claude_id}
                else:
                    ids = {"codex": codex_id}
                verify_cli_reports(str(build / "secure-agent"), ids, set(ids.values()),
                                   str(workspace), environment)
                rows = [json.loads(line) for line in read_required_output(root, "harness.jsonl").splitlines()]
                output = "\n".join(row.get("item", {}).get("aggregated_output", "") for row in rows
                                   if row.get("type") == "item.completed"
                                   and row.get("item", {}).get("type") == "command_execution"
                                   and row.get("item", {}).get("exit_code") == 0)
                if "README.md" not in output or "A small orchard inventory utility." not in output:
                    raise RuntimeError("Harness did not demonstrate successful file listing and README reading")
                if list(workspace.iterdir()) != [workspace / "README.md"] or \
                        (workspace / "README.md").read_text() != "# Orchard\nA small orchard inventory utility.\n":
                    raise RuntimeError("Sample task changed the disposable project")
        finally:
            cleanup_errors = []
            for stream in (locals().get("claude_stream"), locals().get("claude_errors")):
                if stream is not None and not stream.closed:
                    stream.close()
            for child in (native, harness, locals().get("claude_process"), daemon):
                try:
                    stop(child)
                except OSError as error:
                    cleanup_errors.append(str(error))
            for name in ("daemon.log", "native.log", "harness.jsonl", "harness.stderr", "stage", "console-state.json",
                         "claude-trace-shapes.json"):
                source = root / name
                if source.exists():
                    shutil.copyfile(source, build / name)
            shapes = []
            for source in (codex_home / "sessions").rglob("*.jsonl"):
                for line in source.read_text().splitlines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(record, dict) and record.get("type") == "response_item":
                        payload = record.get("payload", {})
                        if isinstance(payload, dict):
                            shapes.append({key: payload[key] for key in ("type", "name", "call_id") if key in payload})
            # Schema diagnostics only; never retain message text or arguments.
            (build / "trace-shapes.json").write_text(json.dumps(shapes))
            if cleanup_errors:
                raise RuntimeError("Child process cleanup failed: " + "; ".join(cleanup_errors))
    print("PASS: fresh-profile Setup → live Codex trace → selected session console" +
          (" + Claude hook decision and exports" if arguments.with_claude else ""))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
