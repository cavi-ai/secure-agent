#!/usr/bin/env python3
"""Opt-in macOS fresh-profile Setup → live Codex → session console check.

Requires an authenticated Codex CLI and a graphical login. Reuses only its
auth.json, in a disposable copy; never imports existing config or transcripts.
No /Applications installation, permissions, hooks or traffic routing is changed.
"""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[2]
TEST = "SetupSessionLiveTests/testFreshProfileToLiveSessionEvidence"


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


def main():
    if sys.platform != "darwin":
        raise RuntimeError("This check requires macOS and a graphical login")
    codex = shutil.which("codex")
    auth = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "auth.json"
    if not codex or not auth.is_file():
        raise RuntimeError("Requires codex on PATH and an authenticated CODEX_HOME/auth.json")

    build = REPO / "dist/setup-session-live"
    build.mkdir(parents=True, exist_ok=True)
    subprocess.run(["go", "build", "-o", str(build / "secure-agentd"),
                    "./daemon/cmd/secure-agentd"], cwd=REPO,
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
        config.write_text(
            "agents:\n  - name: codex\n    match: [" + json.dumps(executable.name) + "]\n"
            "proxy_enabled: true\nproxy_port: 0\nnet_sample_interval_ms: 200\n"
        )
        environment = {key: os.environ[key] for key in ("PATH", "USER", "LOGNAME", "SHELL", "DEVELOPER_DIR")
                       if key in os.environ}
        environment.update({
            "HOME": str(home), "CFFIXED_USER_HOME": str(home),
            "HERMES_HOME": str(home / ".hermes"), "OPENCLAW_HOME": str(home / ".openclaw"),
            "CODEX_HOME": str(codex_home), "SECURE_AGENT_SETUP_E2E_ROOT": str(root),
        })
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
                prompt = (root / "sample-task").read_text()
                harness = subprocess.Popen(
                    [str(executable), "exec", "--ignore-user-config", "--ignore-rules",
                     "--skip-git-repo-check", "--sandbox", "read-only", "--json",
                     "-c", 'cli_auth_credentials_store="file"',
                     "-C", str(workspace), prompt +
                     " Use a shell tool to list the files and read README.md."
                     " Then wait for a shell sleep of 45 seconds to finish before replying."],
                    cwd=workspace, env=environment, stdin=subprocess.DEVNULL,
                    stdout=harness_log, stderr=harness_errors, start_new_session=True)
                result = native.wait(timeout=180)
                sys.stdout.write((root / "native.log").read_text())
                if result:
                    raise RuntimeError("Native Setup/session check failed (see XCTest output)")
                if harness.wait(timeout=90):
                    raise RuntimeError("Live harness failed; see dist/setup-session-live/harness.stderr")
                rows = [json.loads(line) for line in (root / "harness.jsonl").read_text().splitlines()]
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
            for child in (native, harness, daemon):
                try:
                    stop(child)
                except OSError as error:
                    cleanup_errors.append(str(error))
            for name in ("daemon.log", "native.log", "harness.jsonl", "harness.stderr", "stage"):
                source = root / name
                if source.exists():
                    shutil.copyfile(source, build / name)
            if cleanup_errors:
                raise RuntimeError("Child process cleanup failed: " + "; ".join(cleanup_errors))
    print("PASS: fresh-profile Setup → live Codex trace → selected session console")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
