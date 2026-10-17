#!/usr/bin/env python3
"""Real hook/daemon workflow with an isolated, tracked tool-caller fixture.

No model, native dialog or installed harness is simulated as a live client.
The fixture uses the Claude hook protocol; API requests resolve its prompts.
An optional --daemon checks a separately built or packaged daemon binary.
"""

import argparse
from datetime import datetime
import http.client
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import quote


REPO = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(description, check, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError("Timed out: " + description)


def stop(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def run(daemon_binary, harness_binary):
    daemon = harness = None
    # Keep the Unix socket below Darwin's sockaddr_un path limit.
    with tempfile.TemporaryDirectory(prefix="sa-guard-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        home, workspace = root / "home", root / "project"
        home.mkdir(mode=0o700)
        workspace.mkdir()
        resource = home / ".aws" / "credentials"
        resource.parent.mkdir(mode=0o700)
        fixture = "guard workflow fixture\n"
        (workspace / "README.md").write_text(fixture)
        resource.write_text(fixture)
        resource.chmod(0o600)
        other_resource = home / ".config/gcloud/credentials.json"
        other_resource.parent.mkdir(parents=True, mode=0o700)
        other_resource.write_text(fixture)
        other_resource.chmod(0o600)
        modes = root / "guard-modes.json"
        modes.write_text(json.dumps({"cloud-creds": "prompt"}))
        sock = root / "daemon.sock"
        config = root / "config.json"
        config.write_text(json.dumps({
            "agents": [{"name": "claude", "match": [str(harness_binary)]}],
            "socket_path": str(sock), "db_path": str(root / "events.db"),
            "jsonl_path": str(root / "events.jsonl"), "net_sample_interval_ms": 200,
            "directory_guard": {"prompt_deadline_ms": 3000},
        }))
        environment = {key: os.environ[key] for key in ("PATH", "USER", "LOGNAME", "SHELL") if key in os.environ}
        environment.update({
            "HOME": str(home), "CFFIXED_USER_HOME": str(home),
            "CODEX_HOME": str(home / ".codex"), "HERMES_HOME": str(home / ".hermes"),
            "OPENCLAW_HOME": str(home / ".openclaw"),
            "CLAUDE_CODE_ENTRYPOINT": "cli", "SECURE_AGENT_SOCK": str(sock),
            "SECURE_AGENT_SESSION_ID": "guard-workflow-" + uuid.uuid4().hex,
            "SECURE_AGENT_GUARD_MODES": str(modes), "SECURE_AGENT_PROMPT_DEADLINE_S": "10",
        })

        def api(route, body=None, method=None):
            connection = http.client.HTTPConnection("localhost", timeout=5)
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.settimeout(5)
            try:
                connection.sock.connect(str(sock))
                connection.request(method or ("POST" if body is not None else "GET"), route,
                                   json.dumps(body) if body is not None else None,
                                   {"Content-Type": "application/json"})
                response = connection.getresponse()
                content = response.read()
                require(response.status == 200, f"{route}: HTTP {response.status}")
                return json.loads(content)
            finally:
                connection.close()

        def ready():
            require(daemon.poll() is None, "Daemon exited before readiness")
            try:
                return api("/status")
            except (OSError, http.client.HTTPException):
                return None

        def request(operation="read", target=resource):
            harness.stdin.write(operation + "\n")
            harness.stdin.flush()
            pending = wait_for("hook request", lambda: api("/guard/pending"))
            require(len(pending) == 1 and pending[0]["path"] == str(target), "Unexpected pending request")
            return pending[0]

        def result(permission):
            readable, _, _ = select.select([harness.stdout], [], [], 12)
            require(readable, "Tool caller did not return a result")
            line = harness.stdout.readline()
            require(line, "Tool caller exited without a result")
            record = json.loads(line)
            require(record["permission"] == permission, "Unexpected hook verdict: " + record["permission"])
            require(record["bytes_read"] == (len(fixture) if permission == "allow" else 0), "Tool execution did not follow the hook verdict")

        def resolve(pending, verdict="allow", scope="once", expiry=None):
            body = {"id": pending["id"], "verdict": verdict, "scope": scope}
            if expiry:
                body["expiry"] = expiry
            response = api("/guard/resolve", body)
            require(response["resolved"] and response["receipt"]["id"] == pending["id"], "Answer was not submitted to this request")
            return response["receipt"]

        with (root / "daemon.log").open("w+") as daemon_log, (root / "harness.log").open("w+") as harness_log:
            try:
                def start_daemon():
                    return subprocess.Popen([str(daemon_binary), "-config", str(config)], env=environment,
                                            stdout=daemon_log, stderr=daemon_log, start_new_session=True)
                daemon = start_daemon()
                wait_for("daemon", ready)
                harness = subprocess.Popen([str(harness_binary), sys.executable, str(REPO / "plugin/hooks/secret_guard.py"), str(resource), str(other_resource)],
                                           cwd=workspace, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=harness_log, text=True, start_new_session=True)
                harness.stdin.write("observe\n"); harness.stdin.flush()
                result("allow")
                sessions = wait_for("attributed tool caller", lambda: [s for s in api("/sessions") if s.get("root_pid") == harness.pid])
                session_id = sessions[0]["id"]

                pending = request()
                require(pending["session_id"] == session_id and pending["workspace"] == str(workspace), "Request identity does not match the observed session")
                require({s["kind"] for s in pending["available_scopes"]} >= {"once", "session", "exact"}, "Live identity lacks scoped choices")
                require(not resolve(pending).get("scope_ids"), "Once created a future permission")
                result("allow")
                require(api("/decision-scopes") == [], "Once persisted a permission")
                resolve(request(), "deny")
                result("deny")
                print("PASS: allow once and deny control the fixture read", flush=True)

                for scope, expiry, label in (("session", None, "Session permission"), ("exact", "24h", "Timed permission")):
                    pending = request()
                    receipt = resolve(pending, scope=scope, expiry=expiry)
                    result("allow")
                    ids = receipt.get("scope_ids", [])
                    require(len(ids) == 1, "Scoped answer lacks its permission ID")
                    rows = api("/decision-scopes")
                    saved = next(r for r in rows if r["id"] == ids[0])
                    require(saved["applicability"]["label"] == label and saved["resource_path"] == str(resource), "Saved permission does not match approval")
                    require(saved["session_id"] == pending["session_id"] and saved["workspace"] == pending["workspace"]
                            and saved["reader_exe"] == pending["reader_exe"] and saved["operation"] == "guard:Read", "Saved permission changed the recorded identity")
                    if expiry:
                        lifetime = datetime.fromisoformat(saved["expires_at"].replace("Z", "+00:00")) - datetime.fromisoformat(saved["created_at"].replace("Z", "+00:00"))
                        require(86398 <= lifetime.total_seconds() <= 86402, "Timed permission does not expire after 24 hours")
                    harness.stdin.write("read\n"); harness.stdin.flush()
                    result("allow")
                    require(api("/guard/pending") == [], "Saved permission did not resolve the matching request")
                    resolve(request("other", other_resource), "deny")
                    result("deny")
                    revoked = api("/decision-scopes?id=" + quote(ids[0]), method="DELETE")
                    require(revoked["revoked"] and revoked["id"] == ids[0], "Revocation was not confirmed")
                    resolve(request(), "deny")
                    result("deny")
                    print("PASS: " + label + " exact-file reuse, different-file denial and revocation", flush=True)

                pending = request()
                result("deny")
                require(not api("/guard/resolve", {"id": pending["id"], "verdict": "allow", "scope": "once"})["resolved"], "Expired request accepted a late answer")
                outcomes = wait_for("timeout receipt", lambda: next((g for g in api("/sessions/" + quote(session_id) + "/outcomes")["history"]["guards"] if g["id"] == pending["id"]), None))
                require(outcomes["reason"] == "timeout" and outcomes["verdict"] == "deny", "Timeout was not recorded as deny")
                print("PASS: timeout denies the read and rejects a late answer", flush=True)

                stop(daemon)
                harness.stdin.write("read\n"); harness.stdin.flush()
                result("ask")
                print("PASS: unavailable daemon requests Claude consent without reading", flush=True)
                daemon = start_daemon()
                wait_for("restarted daemon", ready)
                wait_for("restored session", lambda: [s for s in api("/sessions") if s.get("root_pid") == harness.pid])
                rows = api("/decision-scopes")
                require(len(rows) == 2 and all(r.get("revoked_at") for r in rows), "Revocations were not retained after restart")
                resolve(request(), "deny")
                result("deny")
                print("PASS: restart retains revocations and permits a fresh decision", flush=True)
            except Exception:
                for stream in (daemon_log, harness_log):
                    stream.flush()
                    stream.seek(0)
                    sys.stderr.write(stream.read()[-4000:])
                raise
            finally:
                stop(harness)
                stop(daemon)
                if harness:
                    harness.stdin.close()
                    harness.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, help="Use this daemon binary instead of building one")
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sa-guard-bin-") as temporary:
        build = Path(temporary)
        daemon = arguments.daemon.resolve() if arguments.daemon else build / "secure-agentd"
        env = {**os.environ, "CGO_ENABLED": "0"}
        if not arguments.daemon:
            subprocess.run(["go", "build", "-o", str(daemon), "./daemon/cmd/secure-agentd"], cwd=REPO, env=env, check=True)
        harness = build / "sa-guard-caller"
        subprocess.run(["go", "build", "-o", str(harness), "./packaging/test/guard-workflow"], cwd=REPO, env=env, check=True)
        run(daemon, harness)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
