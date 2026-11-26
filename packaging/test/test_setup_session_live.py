"""Bounded failure-path checks for the opt-in live setup runner."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("setup_session_live.py")
SPEC = importlib.util.spec_from_file_location("setup_session_live", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class SetupSessionRunnerTests(unittest.TestCase):
    def test_codex_only_session_exports_are_validated(self):
        report = {
            "session": {"id": "codex-one", "harness": "codex", "workspace": "/synthetic"},
            "events": 2, "tool_calls": 1, "timeline": [], "flags": [], "files": [], "hosts": [],
            "tools": [{"key": "shell"}], "guard": [],
        }
        with mock.patch.object(RUNNER.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout=json.dumps(report), stderr=""),
            subprocess.CompletedProcess([], 0, stdout="Session `codex-one`", stderr=""),
        ]):
            result = RUNNER.verify_cli_reports("secure-agent", {"codex": "codex-one"},
                                               {"codex-one"}, "/synthetic", {})
        self.assertEqual(result["codex"]["session"]["id"], "codex-one")

    def test_session_export_rejects_malformed_json_and_schema(self):
        for output in ("not-json", "[]"):
            with self.subTest(output=output), mock.patch.object(RUNNER.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=output, stderr="")):
                expected = "malformed" if output == "not-json" else "invalid shape"
                with self.assertRaisesRegex(RuntimeError, expected):
                    RUNNER.verify_cli_reports("secure-agent", {"codex": "codex-one"},
                                              set(), "/synthetic", {})

    def test_session_export_rejects_shared_identity(self):
        with self.assertRaisesRegex(RuntimeError, "distinct session identities"):
            RUNNER.verify_cli_reports("secure-agent", {"codex": "same", "claude": "same"},
                                      set(), "/synthetic", {})

    def test_claude_collector_link_selects_only_current_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "claude-config"
            old_project = profile / "projects" / "old-workspace"
            current_project = profile / "projects" / "current-workspace"
            old_project.mkdir(parents=True)
            current_project.mkdir(parents=True)
            (old_project / "0cfdde6f-b86f-4dc0-87bb-45eb8f9be2e2.jsonl").write_text("old transcript")
            source = current_project / "c2d7a5ed-5715-43fc-96f0-23f9b2a96246.jsonl"
            source.write_text("new transcript")
            home = root / "home"
            (home / ".claude" / "projects").mkdir(parents=True)
            linked = RUNNER.attach_claude_transcript(home, profile, "c2d7a5ed-5715-43fc-96f0-23f9b2a96246", timeout=0.2)
            self.assertTrue(linked.is_symlink())
            self.assertEqual(linked.resolve(), source.resolve())
            self.assertEqual([path.name for path in (home / ".claude" / "projects" / "live-session").glob("*.jsonl")],
                             ["c2d7a5ed-5715-43fc-96f0-23f9b2a96246.jsonl"])

    def test_claude_session_id_must_be_canonical_uuid_before_path_use(self):
        self.assertTrue(RUNNER.is_valid_claude_session_id("c2d7a5ed-5715-43fc-96f0-23f9b2a96246"))
        self.assertFalse(RUNNER.is_valid_claude_session_id("../../old-session"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "canonical UUID"):
                RUNNER.attach_claude_transcript(root / "home", root / "profile", "../../old-session")
            self.assertFalse((root / "home").exists())

    def test_denied_marker_is_rejected_anywhere_in_stream(self):
        denied = {"is_error": True, "content": "Permission denied"}
        RUNNER.verify_denied_stream('{"type":"tool_result","content":"Permission denied"}', denied)
        with self.assertRaisesRegex(RuntimeError, "exposed the synthetic denied file"):
            RUNNER.verify_denied_stream(
                '{"type":"assistant","text":"SAFE_DENIED_EVIDENCE=deny-once-proof"}', denied)

    def test_native_claude_copy_requires_successful_version_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "claude"
            source.write_text("standalone native executable")
            source.chmod(0o700)
            destination = root / "isolated-claude"
            with mock.patch.object(RUNNER.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 0, stdout="", stderr="")) as run:
                copied = RUNNER.prepare_claude_executable(source, destination, {})
            self.assertEqual(copied.read_text(), source.read_text())
            self.assertEqual(run.call_args.args[0], [str(destination), "--version"])
            destination.unlink()
            with mock.patch.object(RUNNER.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 1, stdout="", stderr="")):
                with self.assertRaisesRegex(RuntimeError, "standalone executable"):
                    RUNNER.prepare_claude_executable(source, destination, {})
            self.assertFalse(destination.exists())

    def test_auth_false_and_malformed_status_fail_without_echoing_output(self):
        for output in ('{"loggedIn": false}', 'not-json: token-secret'):
            with self.subTest(output=output), mock.patch.object(
                RUNNER.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0 if output.startswith("{") else 0,
                                                          stdout=output, stderr="credential-secret"),
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "Existing Claude authentication is unavailable") as raised:
                    RUNNER.require_claude_authentication("claude", {"CLAUDE_CONFIG_DIR": "/isolated"})
                self.assertNotIn("secret", str(raised.exception))
                run.assert_called_once()
                self.assertEqual(run.call_args.args[0][1:], ["auth", "status", "--json"])
                self.assertEqual(run.call_args.kwargs["env"]["CLAUDE_CONFIG_DIR"], "/isolated")

    def test_authenticated_status_requires_json_boolean_true(self):
        with mock.patch.object(RUNNER.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, stdout='{"loggedIn": true}', stderr="")):
            self.assertTrue(RUNNER.claude_authentication_status("claude", {}))
        with mock.patch.object(RUNNER.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, stdout='{"loggedIn": "true"}', stderr="")):
            self.assertFalse(RUNNER.claude_authentication_status("claude", {}))

    def test_existing_claude_config_uses_configured_or_default_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configured = root / "configured"
            default = root / ".claude"
            configured.mkdir()
            default.mkdir()
            self.assertEqual(RUNNER.existing_claude_config_dir(None, {"CLAUDE_CONFIG_DIR": str(configured)}),
                             configured.resolve())
            self.assertEqual(RUNNER.existing_claude_config_dir(configured, {}), configured.resolve())
            with mock.patch.object(RUNNER.Path, "home", return_value=root):
                self.assertEqual(RUNNER.existing_claude_config_dir(None, {}), default.resolve())
            missing = root / "missing"
            with self.assertRaisesRegex(RuntimeError, "Existing Claude config directory is unavailable"):
                RUNNER.existing_claude_config_dir(missing, {})
            self.assertFalse(missing.exists())

    def test_missing_child_output_is_bounded_and_names_only_marker(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "Missing required child output: sample-task"):
                RUNNER.read_required_output(root, "sample-task")

    def test_marker_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "Timed out waiting for ready"):
                RUNNER.wait_for_path(Path(root) / "ready", timeout=0, interval=0)

    def test_cleanup_signals_only_root_and_descendants(self):
        process = mock.Mock()
        process.pid = 101
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch.object(RUNNER.subprocess, "check_output", return_value="101 1\n102 101\n103 102\n999 1\n"), \
                mock.patch.object(RUNNER.os, "kill") as kill:
            RUNNER.stop(process)
        self.assertEqual([call.args[0] for call in kill.call_args_list], [103, 102, 101])
        process.wait.assert_called_once_with(timeout=5)

    def test_wait_timeout_raises_subprocess_timeout_for_cleanup_path(self):
        process = mock.Mock()
        process.wait.side_effect = subprocess.TimeoutExpired(["child"], 1)
        with self.assertRaisesRegex(RuntimeError, "Timed out waiting for sample Claude"):
            RUNNER.wait_for_child(process, 1, "sample Claude")


if __name__ == "__main__":
    unittest.main()
