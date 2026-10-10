import copy
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import build


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = {
            "schemaVersion": 1, "product": "secure-agent", "package": "secure-agent",
            "version": "1.2.3", "source": {"commit": "a" * 40, "dirty": False},
            "release": {"tag": "v1.2.3", "commit": "a" * 40},
            "generatedAt": "2026-01-01T00:00:00Z",
            "publicBasePath": "/docs/secure-agent/v1.2.3", "stableAlias": "/docs/secure-agent",
        }

    def artifact(self):
        directory = self.root / "artifact"
        directory.mkdir()
        (directory / "README.md").write_text("# Start\n\n[Details](docs/details.md#result)\n")
        (directory / "docs").mkdir()
        (directory / "docs/details.md").write_text("# Result\n\nA documented result.\n")
        nav = {"sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "README.md"}, {"title": "Details", "path": "docs/details.md"}]}]}
        (directory / "navigation.json").write_text(json.dumps(nav))
        self.seal(directory)
        return directory

    def seal(self, directory):
        manifest = {**self.manifest, "contentSha256": build.digest(directory)}
        (directory / "manifest.json").write_text(json.dumps(manifest))

    def test_digest_matches_published_contract_and_detects_tampering(self):
        directory = self.artifact()
        hashed = hashlib.sha256()
        for name in ("README.md", "docs/details.md", "navigation.json"):
            hashed.update(name.encode() + b"\0" + (directory / name).read_bytes() + b"\0")
        self.assertEqual(build.digest(directory), hashed.hexdigest())
        build.verify(directory)
        build.verify(Path(os.path.relpath(directory)))
        (directory / "README.md").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            build.verify(directory)

    def test_missing_pages_and_anchors_fail_even_with_updated_digest(self):
        directory = self.artifact()
        (directory / "docs/details.md").write_text("# Changed heading\n")
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "anchor"):
            build.verify(directory)
        (directory / "README.md").unlink()
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "page"):
            build.verify(directory)

    def test_artifact_rejects_path_escape_and_release_provenance_mismatch(self):
        directory = self.artifact()
        nav = {"sections": [{"title": "Bad", "pages": [{"title": "Outside", "path": "../outside.md"}]}]}
        (self.root / "outside.md").write_text("# Outside\n")
        (directory / "navigation.json").write_text(json.dumps(nav))
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            build.verify(directory)
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["release"]["commit"] = "b" * 40
        (directory / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "provenance"):
            build.verify(directory)

    def test_release_identity_rejects_dirty_tree_wrong_tag_and_wrong_commit(self):
        def command(*args, **kwargs):
            if args[1:3] == ("status", "--porcelain"):
                return " M docs/README.md\n"
            if args[1:3] == ("log", "-1"):
                return "1767225600\n"
            return "a" * 40 + "\n"

        with patch.object(build, "run", side_effect=command):
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                build.identity("1.2.3", "v1.2.3")
            with self.assertRaisesRegex(ValueError, "require"):
                build.identity("1.2.3", "v1.2.4")
            manifest, _ = build.identity()
            self.assertTrue(manifest["source"]["dirty"])
            self.assertIsNone(manifest["publicBasePath"])
        def wrong_commit(*args, **kwargs):
            if args[1] == "status":
                return ""
            if args[1] == "log":
                return "1767225600\n"
            return ("b" if "refs/tags/" in args[-1] else "a") * 40 + "\n"
        with patch.object(build, "run", side_effect=wrong_commit):
            with self.assertRaisesRegex(ValueError, "does not identify HEAD"):
                build.identity("1.2.3", "v1.2.3")

    def test_archive_is_deterministic_and_refuses_different_bytes(self):
        directory = self.artifact()
        (self.root / "dist").mkdir()
        with patch.object(build, "ROOT", self.root):
            path = build.archive(directory, self.manifest, 1767225600)
            before = path.read_bytes()
            path.unlink()
            Path(str(path) + ".sha256").unlink()
            build.archive(directory, self.manifest, 1767225600)
            self.assertEqual(before, path.read_bytes())
            with tarfile.open(path) as archive:
                self.assertTrue(all(member.name.startswith("docs/secure-agent/v1.2.3/") for member in archive))
                self.assertTrue(all(member.uid == 0 and member.gid == 0 and member.mode == 0o644 for member in archive))
            (directory / "README.md").write_text("changed")
            with self.assertRaisesRegex(ValueError, "immutable"):
                build.archive(directory, self.manifest, 1767225600)

    def test_artifact_rejects_symbolic_links(self):
        directory = self.artifact()
        (self.root / "outside.txt").write_text("external content")
        (directory / "external.txt").symlink_to(self.root / "outside.txt")
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            build.verify(directory)

    def test_navigation_requires_all_pages_once(self):
        (self.root / "docs").mkdir()
        nav = {"sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "README.md"}]}]}
        (self.root / "README.md").write_text("# Overview\n")
        (self.root / "docs/navigation.json").write_text(json.dumps(nav))
        with patch.object(build, "ROOT", self.root), patch.object(build, "documents", return_value=[self.root / "README.md", self.root / "docs/missing.md"]):
            with self.assertRaisesRegex(ValueError, "every page once"):
                build.navigation()
        nav["sections"][0]["pages"].append(copy.deepcopy(nav["sections"][0]["pages"][0]))
        (self.root / "docs/navigation.json").write_text(json.dumps(nav))
        with patch.object(build, "ROOT", self.root), patch.object(build, "documents", return_value=[self.root / "README.md"]):
            with self.assertRaisesRegex(ValueError, "every page once"):
                build.navigation()


if __name__ == "__main__":
    unittest.main()
