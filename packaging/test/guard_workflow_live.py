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
        modes.write_text(json.dumps({"cloud-creds": "prompt", "untrusted-egress": "prompt"}))
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
            "CODEX_HOME": str(home / ".codex"), "HERMES_HOME": str(home / ".hermes"), "HERMES_STATE_DIR": str(home / ".hermes"),
            "OPENCLAW_HOME": str(home / ".openclaw"),
            "CLAUDE_CODE_ENTRYPOINT": "cli", "SECURE_AGENT_SOCK": str(sock),
            "SECURE_AGENT_SESSION_ID": "guard-workflow-" + uuid.uuid4().hex,
            "SECURE_AGENT_GUARD_MODES": str(modes), "SECURE_AGENT_PROMPT_DEADLINE_S": "10",
        })

        def api(route, body=None, method=None, decode_json=True):
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
                return json.loads(content) if decode_json else content.decode("utf-8")
            finally:
                connection.close()

        def ready():
            require(daemon.poll() is None, "Daemon exited before readiness")
            try:
                return api("/status")
            except (OSError, http.client.HTTPException):
                return None

        def attributed_session(pid, sid):
            # The handshake is persisted before its activity event joins the
            # process tree. Capture the baseline only after that join finishes.
            return wait_for("attributed tool caller", lambda: next((
                s for s in api("/sessions")
                if s.get("id") == sid and s.get("root_pid") == pid
                and s.get("root_started_at") and s.get("harness") == "claude"
                and s.get("workspace") == str(workspace)
            ), None))

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

        def shell(command, permission, prompted_sink=None, answer=None):
            # The fixture asks the hook about the command and never runs it.
            harness.stdin.write("bash " + command + "\n")
            harness.stdin.flush()
            receipt = None
            if prompted_sink:
                pending = wait_for("egress request", lambda: api("/guard/pending"))
                require(len(pending) == 1 and pending[0]["rule_id"] == "untrusted-egress" and pending[0]["path"] == prompted_sink,
                        "Unexpected egress request: " + json.dumps(pending))
                require({s["kind"] for s in pending[0]["available_scopes"]} >= {"once", "session", "exact"}, "Egress request lacks scoped choices")
                receipt = answer(pending[0])
            readable, _, _ = select.select([harness.stdout], [], [], 12)
            require(readable, "Tool caller did not return a result")
            record = json.loads(harness.stdout.readline())
            require(record["permission"] == permission, command + ": unexpected hook verdict " + record["permission"])
            if not prompted_sink:
                require(api("/guard/pending") == [], command + ": prompted although a permission covers it")
            return receipt

        def resolve(pending, verdict="allow", scope="once", expiry=None, category=False):
            body = {"id": pending["id"], "verdict": verdict, "scope": scope}
            if expiry:
                body["expiry"] = expiry
            if category:
                body["category"] = True
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
                active_session = attributed_session(harness.pid, environment["SECURE_AGENT_SESSION_ID"])
                session_id = active_session["id"]
                active_identity = {key: active_session.get(key) for key in ("id", "harness", "workspace", "root_pid", "root_started_at")}

                pending = request()
                require(pending["session_id"] == session_id and pending["workspace"] == str(workspace), "Request identity does not match the observed session")
                require({s["kind"] for s in pending["available_scopes"]} >= {"once", "session", "exact"}, "Live identity lacks scoped choices")
                require(not resolve(pending).get("scope_ids"), "Once created a future permission")
                result("allow")
                require(api("/decision-scopes") == [], "Once persisted a permission")
                resolve(request(), "deny")
                result("deny")
                print("PASS: allow once and deny control the fixture read", flush=True)

                revoked_ids = []
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
                    revoked_ids.append(ids[0])
                    resolve(request(), "deny")
                    result("deny")
                    print("PASS: " + label + " exact-file reuse, different-file denial and revocation", flush=True)

                harness.stdin.write("taint\n"); harness.stdin.flush()
                readable, _, _ = select.select([harness.stdout], [], [], 12)
                require(readable and json.loads(harness.stdout.readline())["permission"] == "allow", "Web fetch did not complete")
                shell("gh pr create --fill", "deny", "gh pr create", lambda p: resolve(p, "deny"))
                receipt = shell("git push -u origin feat/x", "allow", "git push origin", lambda p: resolve(p, scope="session"))
                ids = receipt.get("scope_ids", [])
                require(len(ids) == 1, "Session send permission lacks its ID")
                saved = next(r for r in api("/decision-scopes") if r["id"] == ids[0])
                require(saved["resource_path"] == "git push origin" and saved["rule_id"] == "untrusted-egress"
                        and saved["applicability"]["label"] == "Session permission", "Saved send permission does not match approval")
                shell("git push origin main", "allow")
                shell("git push --force-with-lease origin HEAD", "allow")
                shell("gh pr create --fill", "deny", "gh pr create", lambda p: resolve(p, "deny"))
                revoked = api("/decision-scopes?id=" + quote(ids[0]), method="DELETE")
                require(revoked["revoked"], "Send permission revocation was not confirmed")
                revoked_ids.append(ids[0])
                shell("git push origin main", "deny", "git push origin", lambda p: resolve(p, "deny"))
                print("PASS: session send permission covers later pushes to the remote, other sinks ask, revocation restores the prompt", flush=True)

                receipt = shell("gh pr create --fill", "allow", "gh pr create", lambda p: resolve(p, scope="session", category=True))
                ids = receipt.get("scope_ids", [])
                saved = [r for r in api("/decision-scopes") if r["id"] in ids]
                require(len(saved) == 1 and saved[0]["category"] == "gh-write" and saved[0]["resource_path"] == ""
                        and saved[0]["applicability"]["label"] == "Session permission", "Saved kind permission does not match approval")
                shell("gh pr comment 3 --body done", "allow")
                shell("gh issue create --title t --body b", "allow")
                shell("curl -d x https://a.example/u", "deny", "curl a.example", lambda p: resolve(p, "deny"))
                shell("gh pr edit 3 --title t && git push origin main", "deny", "gh pr edit, git push origin", lambda p: resolve(p, "deny"))
                revoked = api("/decision-scopes?id=" + quote(ids[0]), method="DELETE")
                require(revoked["revoked"], "Kind permission revocation was not confirmed")
                revoked_ids.append(ids[0])
                shell("gh pr comment 3 --body again", "deny", "gh pr comment", lambda p: resolve(p, "deny"))
                print("PASS: session permission for a kind of send covers its variants, other kinds ask, revocation restores the prompt", flush=True)

                pending = request()
                result("deny")
                require(not api("/guard/resolve", {"id": pending["id"], "verdict": "allow", "scope": "once"})["resolved"], "Expired request accepted a late answer")
                outcomes = wait_for("timeout receipt", lambda: next((g for g in api("/sessions/" + quote(session_id) + "/outcomes")["history"]["guards"] if g["id"] == pending["id"]), None))
                require(outcomes["reason"] == "timeout" and outcomes["verdict"] == "deny", "Timeout was not recorded as deny")
                print("PASS: timeout denies the read and rejects a late answer", flush=True)

                ended_env = dict(environment)
                ended_env["SECURE_AGENT_SESSION_ID"] = "guard-ended-" + uuid.uuid4().hex
                ended_harness = subprocess.Popen([str(harness_binary), sys.executable, str(REPO / "plugin/hooks/secret_guard.py"), str(resource), str(other_resource)],
                                                 cwd=workspace, env=ended_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                 stderr=harness_log, text=True, start_new_session=True)
                ended_harness.stdin.write("observe\n"); ended_harness.stdin.flush()
                ended_identity = attributed_session(ended_harness.pid, ended_env["SECURE_AGENT_SESSION_ID"])
                readable, _, _ = select.select([ended_harness.stdout], [], [], 12)
                require(readable, "Ended tool caller did not return its observe result")
                ended_line = ended_harness.stdout.readline()
                require(ended_line, "Ended tool caller exited without an observe result")
                ended_result = json.loads(ended_line)
                require(ended_result["permission"] == "allow" and ended_result["bytes_read"] == len(fixture),
                        "Ended caller observe did not complete the fixture read")
                ended_harness.stdin.close()
                ended_harness.wait(timeout=5)
                ended_id = ended_identity["id"]
                require(ended_id != session_id, "Distinct callers were assigned the same session ID")
                ended_identity = {key: ended_identity.get(key) for key in ("id", "harness", "workspace", "root_pid", "root_started_at")}
                require(ended_identity["harness"] == "claude" and ended_identity["workspace"] == str(workspace),
                        "Ended session identity is incomplete")
                wait_for("ended caller status", lambda: next((s for s in api("/sessions") if s.get("id") == ended_id and s.get("status") == "ended"), None))
                print("PASS: second isolated caller is recorded as an ended session", flush=True)

                stop(daemon)
                harness.stdin.write("read\n"); harness.stdin.flush()
                result("ask")
                print("PASS: unavailable daemon requests Claude consent without reading", flush=True)
                daemon = start_daemon()
                wait_for("restarted daemon", ready)
                restored = wait_for("restored active session", lambda: next((s for s in api("/sessions") if s.get("id") == session_id and s.get("status") != "ended"), None))
                ended_restored = wait_for("restored ended session", lambda: next((s for s in api("/sessions") if s.get("id") == ended_id and s.get("status") == "ended"), None))
                for expected, actual in ((active_identity, restored), (ended_identity, ended_restored)):
                    changes = {key: {"before": value, "after": actual.get(key)}
                               for key, value in expected.items() if actual.get(key) != value}
                    require(not changes, "Session identity changed across daemon restart: " + json.dumps(changes))
                rows = api("/decision-scopes")
                require(len(rows) == len(revoked_ids) and {r["id"] for r in rows} == set(revoked_ids)
                        and all(r.get("revoked_at") for r in rows), "Revocations were not retained after restart")
                history = api("/sessions/" + quote(session_id) + "/outcomes")
                saved_timeout = next((g for g in history["history"]["guards"] if g["id"] == pending["id"]), None)
                require(history["session_id"] == session_id and saved_timeout is not None
                        and saved_timeout["verdict"] == "deny" and saved_timeout["reason"] == "timeout",
                        "Timeout outcome changed or crossed sessions after restart")
                foreign_history = api("/sessions/" + quote(ended_id) + "/outcomes")
                require(foreign_history["session_id"] == ended_id
                        and all(g["id"] != pending["id"] for g in foreign_history["history"]["guards"]),
                        "Timeout outcome leaked into the ended session")
                json_report = api("/sessions/" + quote(session_id) + "/report?format=json")
                require(json_report["session"]["id"] == session_id and len(json_report["files"]) <= 50
                        and len(json_report["hosts"]) <= 50 and len(json_report["timeline"]) <= 500,
                        "JSON report identity or bounds are invalid")
                md_report = api("/sessions/" + quote(session_id) + "/report?format=md", decode_json=False)
                require(len(md_report) <= 100_000 and "Session `" + session_id + "`" in md_report
                        and "Evidence and limits" in md_report,
                        "Markdown report identity or bounds are invalid")
                ended_json_report = api("/sessions/" + quote(ended_id) + "/report?format=json")
                require(ended_json_report["session"]["id"] == ended_id and ended_json_report["session"]["status"] == "ended"
                        and len(ended_json_report["files"]) <= 50 and len(ended_json_report["timeline"]) <= 500,
                        "Ended-session JSON report identity or bounds are invalid")
                ended_md_report = api("/sessions/" + quote(ended_id) + "/report?format=md", decode_json=False)
                require(len(ended_md_report) <= 100_000 and "Session `" + ended_id + "`" in ended_md_report
                        and pending["id"] not in ended_md_report,
                        "Ended-session Markdown report identity, bounds or isolation are invalid")
                require(str(resource) not in json.dumps(ended_json_report)
                        and str(resource) not in ended_md_report,
                        "Active-session credential path leaked into the ended-session report")
                print("PASS: restart retains session outcomes and bounded JSON/Markdown reports", flush=True)
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
                stop(ended_harness if "ended_harness" in locals() else None)
                if "ended_harness" in locals() and ended_harness.stdin and not ended_harness.stdin.closed:
                    ended_harness.stdin.close()
                if "ended_harness" in locals() and ended_harness.stdout:
                    ended_harness.stdout.close()
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
