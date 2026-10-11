import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build
import publish


class ReleaseDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        # A synthetic commit in a disposable fixture repository. Product tags,
        # signatures, hooks and history are never touched by these tests.
        tree = self.git("hash-object", "-t", "tree", "-w", "--stdin", body="")
        commit = f"tree {tree}\nauthor Fixture <fixture@example.com> 1767225600 +0000\ncommitter Fixture <fixture@example.com> 1767225600 +0000\n\nfixture\n"
        self.commit = self.git("hash-object", "-t", "commit", "-w", "--stdin", body=commit)
        self.git("update-ref", "refs/heads/fixture", self.commit)
        self.git("symbolic-ref", "HEAD", "refs/heads/fixture")
        self.git("update-ref", "refs/tags/v1.2.3", self.commit)
        (self.root / ".git/info/exclude").write_text("dist/\n")
        self.addCleanup(patch.stopall)
        patch.object(build, "ROOT", self.root).start()
        self.manifest, self.epoch = build.identity("1.2.3", "v1.2.3")
        self.directory = self.root / "dist/content"
        self.directory.mkdir(parents=True)
        (self.directory / "readme.md").write_text("# Fixture documentation\n")
        nav = {"title": "Secure Agent", "version": "1.2.3", "sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "readme.md"}]}]}
        (self.directory / "navigation.json").write_text(json.dumps(nav))
        self.seal()
        self.archive = build.archive(self.directory, self.manifest, self.epoch)
        self.sidecar = Path(str(self.archive) + ".sha256")
        self.envelope = self.archive.with_name("secure-agent-docs-v1.2.3.release.json")
        self.assets = [self.archive, self.sidecar, self.envelope]

    def git(self, *args, body=None):
        return subprocess.run(["git", "-C", str(self.root), *args], input=body,
                              text=True, capture_output=True, check=True).stdout.strip()

    def seal(self):
        manifest = {**self.manifest, "contentSha256": build.digest(self.directory)}
        (self.directory / "manifest.json").write_text(json.dumps(manifest))

    def checksum(self):
        self.sidecar.write_text(f"{hashlib.sha256(self.archive.read_bytes()).hexdigest()}  {self.archive.name}\n")

    def test_verify_actual_tag_archive_and_default_preview_has_no_remote_calls(self):
        self.assertEqual(publish.verify_release("v1.2.3"), self.assets)
        with patch.object(sys, "argv", ["publish.py", "--tag", "v1.2.3"]), patch.object(publish, "gh") as remote:
            publish.main()
            remote.assert_not_called()

    def test_bad_checksum_and_wrong_embedded_commit_are_rejected(self):
        self.sidecar.write_text("invalid checksum\n")
        with self.assertRaisesRegex(ValueError, "checksum"):
            publish.verify_release("v1.2.3")
        self.manifest["source"]["commit"] = "b" * 40
        self.manifest["release"]["commit"] = "b" * 40
        self.seal()
        self.archive.unlink()
        self.sidecar.unlink()
        self.envelope.unlink()
        build.archive(self.directory, self.manifest, self.epoch)
        with self.assertRaisesRegex(ValueError, "checked-out product tag"):
            publish.verify_release("v1.2.3")

    def test_dirty_checkout_and_tag_moved_to_other_commit_are_rejected(self):
        (self.root / "untracked.txt").write_text("fixture change")
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            publish.verify_release("v1.2.3")
        (self.root / "untracked.txt").unlink()
        tree = self.git("rev-parse", "HEAD^{tree}")
        body = f"tree {tree}\nauthor Fixture <fixture@example.com> 1767225601 +0000\ncommitter Fixture <fixture@example.com> 1767225601 +0000\n\nanother fixture\n"
        other = self.git("hash-object", "-t", "commit", "-w", "--stdin", body=body)
        self.git("update-ref", "refs/tags/v1.2.3", other)
        with self.assertRaisesRegex(ValueError, "does not identify HEAD"):
            publish.verify_release("v1.2.3")

    def test_unsafe_or_duplicate_archive_entries_are_rejected(self):
        for name, kind in [("../escape", tarfile.REGTYPE), ("docs/secure-agent/v1.2.3/link", tarfile.SYMTYPE), ("docs/secure-agent/v9.9.9/readme.md", tarfile.REGTYPE), ("duplicate", tarfile.REGTYPE)]:
            with self.subTest(name=name):
                with tarfile.open(self.archive, "w:gz") as archive:
                    names = ["docs/secure-agent/v1.2.3/readme.md"] * 2 if name == "duplicate" else [name]
                    for entry in names:
                        info = tarfile.TarInfo(entry)
                        info.type, info.size = kind, 0
                        archive.addfile(info, io.BytesIO())
                self.checksum()
                with self.assertRaisesRegex(ValueError, "archive entry"):
                    publish.verify_release("v1.2.3")

    def remote(self, existing=None, **state):
        existing = existing or {}
        release = {"tagName": "v1.2.3", "isDraft": False, "isPrerelease": False,
                   "assets": [{"name": name} for name in existing], **state}
        calls = []

        def command(*args, **kwargs):
            calls.append(args)
            if args[:2] == ("release", "view"):
                return json.dumps(release)
            if args[0] == "api":
                return self.commit
            if args[:2] == ("release", "download"):
                name = args[args.index("--pattern") + 1]
                Path(args[args.index("--output") + 1]).write_bytes(existing[name])
            return ""

        return patch.object(publish, "gh", side_effect=command), calls

    def test_uploads_only_missing_assets_and_never_clobbers(self):
        remote, calls = self.remote({self.archive.name: self.archive.read_bytes()})
        with remote:
            publish.publish("v1.2.3", "example/product", self.assets)
        uploads = [call for call in calls if call[:2] == ("release", "upload")]
        self.assertEqual(uploads, [("release", "upload", "v1.2.3", str(self.sidecar), str(self.envelope), "--repo", "example/product")])

    def test_identical_assets_are_an_idempotent_noop(self):
        remote, calls = self.remote({asset.name: asset.read_bytes() for asset in self.assets})
        with remote:
            publish.publish("v1.2.3", "example/product", self.assets)
        self.assertFalse(any(call[:2] == ("release", "upload") for call in calls))

    def test_mismatched_asset_prevents_all_uploads(self):
        for asset in self.assets:
            with self.subTest(asset=asset.name):
                remote, calls = self.remote({asset.name: b"different bytes"})
                with remote, self.assertRaisesRegex(ValueError, "refusing overwrite"):
                    publish.publish("v1.2.3", "example/product", self.assets)
                self.assertFalse(any(call[:2] == ("release", "upload") for call in calls))

    def test_draft_prerelease_or_mismatched_release_refuses_upload(self):
        for state in [{"isDraft": True}, {"isPrerelease": True}, {"tagName": "v9.9.9"}]:
            with self.subTest(state=state):
                remote, calls = self.remote(**state)
                with remote, self.assertRaisesRegex(ValueError, "published stable release"):
                    publish.publish("v1.2.3", "example/product", self.assets)
                self.assertFalse(any(call[:2] == ("release", "upload") for call in calls))

    def test_remote_tag_change_prevents_upload(self):
        release = {"tagName": "v1.2.3", "isDraft": False, "isPrerelease": False, "assets": []}
        with patch.object(publish, "gh", side_effect=[json.dumps(release), "b" * 40]) as remote:
            with self.assertRaisesRegex(ValueError, "remote product tag"):
                publish.publish("v1.2.3", "example/product", self.assets)
            self.assertFalse(any(call.args[:2] == ("release", "upload") for call in remote.call_args_list))

    def test_existing_asset_download_failure_does_not_trigger_upload(self):
        release = {"tagName": "v1.2.3", "isDraft": False, "isPrerelease": False,
                   "assets": [{"name": self.archive.name}]}
        with patch.object(publish, "gh", side_effect=[json.dumps(release), self.commit, ValueError("download unavailable")]) as remote:
            with self.assertRaisesRegex(ValueError, "download unavailable"):
                publish.publish("v1.2.3", "example/product", self.assets)
            self.assertFalse(any(call.args[:2] == ("release", "upload") for call in remote.call_args_list))

    def test_envelope_and_archive_provenance_must_match(self):
        envelope = json.loads(self.envelope.read_text())
        envelope["artifact"]["sha256"] = "a" * 64
        self.envelope.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(ValueError, "release envelope"):
            publish.verify_release("v1.2.3")
        with tarfile.open(self.archive) as source:
            members = [(member, source.extractfile(member).read()) for member in source]
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as target:
            for member, body in members:
                if member.name == "cavi-release.json":
                    metadata = json.loads(body)
                    metadata["commit"] = "b" * 40
                    body = json.dumps(metadata).encode()
                    member.size = len(body)
                target.addfile(member, io.BytesIO(body))
        self.checksum()
        with self.assertRaisesRegex(ValueError, "cavi-release.json"):
            publish.verify_release("v1.2.3")

    def test_notification_requires_publication_and_dispatch_token_before_remote_calls(self):
        for args in [["--notify-cavi-home"], ["--publish", "--repo", "cavi-ai/secure-agent", "--notify-cavi-home"], ["--publish", "--repo", "example/product"]]:
            with patch.dict(os.environ, {}, clear=True), patch.object(sys, "argv", ["publish.py", "--tag", "v1.2.3", *args]), patch.object(publish, "gh") as remote:
                with self.assertRaises(SystemExit):
                    publish.main()
                remote.assert_not_called()

    def test_notification_follows_successful_publication_and_uses_verified_envelope(self):
        remote, calls = self.remote()
        with remote as gh, patch.dict(os.environ, {"CONSUMER_DISPATCH_TOKEN": "fixture-token"}), patch.object(sys, "argv", ["publish.py", "--tag", "v1.2.3", "--repo", "cavi-ai/secure-agent", "--publish", "--notify-cavi-home"]):
            publish.main()
            request = gh.call_args
        self.assertEqual(calls[-2][:2], ("release", "upload"))
        self.assertEqual(request.args, ("api", "--method", "POST", "repos/cavi-ai/cavi-home/dispatches", "--input", "-"))
        self.assertEqual(json.loads(request.kwargs["body"]), {"event_type": "cavi-oss-release", "client_payload": json.loads(self.envelope.read_text())})
        self.assertEqual(request.kwargs["token"], "fixture-token")

    def test_failed_publication_does_not_dispatch_and_failed_dispatch_is_an_error(self):
        argv = ["publish.py", "--tag", "v1.2.3", "--repo", "cavi-ai/secure-agent", "--publish", "--notify-cavi-home"]
        with patch.dict(os.environ, {"CONSUMER_DISPATCH_TOKEN": "fixture-token"}), patch.object(sys, "argv", argv):
            with patch.object(publish, "publish", side_effect=ValueError("upload failed")), patch.object(publish, "notify_cavi_home") as notify:
                with self.assertRaisesRegex(ValueError, "upload failed"):
                    publish.main()
                notify.assert_not_called()
            with patch.object(publish, "publish"), patch.object(publish, "gh", side_effect=ValueError("dispatch failed")):
                with self.assertRaisesRegex(ValueError, "dispatch failed"):
                    publish.main()


if __name__ == "__main__":
    unittest.main()
