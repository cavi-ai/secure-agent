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
        self.root = Path(self.temp.name).resolve()
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
        (directory / "readme.md").write_text("# Start\n\n[Details](docs/details.md#result)\n")
        (directory / "docs").mkdir()
        (directory / "docs/details.md").write_text("# Result\n\nA documented result.\n")
        nav = {"title": "Secure Agent", "version": "1.2.3", "sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "readme.md"}, {"title": "Details", "path": "docs/details.md"}]}]}
        (directory / "navigation.json").write_text(json.dumps(nav))
        self.seal(directory)
        return directory

    def seal(self, directory):
        manifest = {**self.manifest, "contentSha256": build.digest(directory)}
        (directory / "manifest.json").write_text(json.dumps(manifest))

    def test_digest_matches_published_contract_and_detects_tampering(self):
        directory = self.artifact()
        hashed = hashlib.sha256()
        for name in ("docs/details.md", "navigation.json", "readme.md"):
            hashed.update(name.encode() + b"\0" + (directory / name).read_bytes() + b"\0")
        self.assertEqual(build.digest(directory), hashed.hexdigest())
        build.verify(directory)
        build.verify(Path(os.path.relpath(directory)))
        (directory / "readme.md").write_text("tampered")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            build.verify(directory)

    def test_missing_pages_and_anchors_fail_even_with_updated_digest(self):
        directory = self.artifact()
        (directory / "docs/details.md").write_text("# Changed heading\n")
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "anchor"):
            build.verify(directory)
        (directory / "readme.md").unlink()
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "page"):
            build.verify(directory)

    def test_artifact_rejects_path_escape_and_release_provenance_mismatch(self):
        directory = self.artifact()
        nav = {"title": "Secure Agent", "version": "1.2.3", "sections": [{"title": "Bad", "pages": [{"title": "Outside", "path": "../outside.md"}]}]}
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
                return " M docs/readme.md\n"
            if args[1:3] == ("log", "-1"):
                return "1767225600\n"
            return "a" * 40 + "\n"

        with patch.object(build, "run", side_effect=command):
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                build.identity("1.2.3", "v1.2.3")
            with self.assertRaisesRegex(ValueError, "require"):
                build.identity("1.2.3", "v1.2.4")
            for version in ("01.2.3", "1.2.3-.", "1.2.3-beta..1"):
                with self.assertRaisesRegex(ValueError, "require"):
                    build.identity(version, f"v{version}")
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
            envelope_path = path.with_name("secure-agent-docs-v1.2.3.release.json")
            envelope_before = envelope_path.read_bytes()
            envelope_path.unlink()
            build.archive(directory, self.manifest, 1767225600)
            self.assertEqual(before, path.read_bytes())
            self.assertEqual(envelope_before, envelope_path.read_bytes())
            with tarfile.open(path) as archive:
                self.assertTrue(all(member.name == "cavi-release.json" or member.name.startswith("docs/secure-agent/v1.2.3/") for member in archive))
                self.assertTrue(all(member.uid == 0 and member.gid == 0 and member.mode == 0o644 for member in archive))
                self.assertEqual(json.load(archive.extractfile("cavi-release.json")), build.release_metadata(self.manifest))
            (directory / "readme.md").write_text("changed")
            with self.assertRaisesRegex(ValueError, "immutable"):
                build.archive(directory, self.manifest, 1767225600)

    def test_navigation_identity_mismatch_and_development_envelope_are_rejected(self):
        directory = self.artifact()
        nav = json.loads((directory / "navigation.json").read_text())
        nav["version"] = "9.9.9"
        (directory / "navigation.json").write_text(json.dumps(nav))
        self.seal(directory)
        with self.assertRaisesRegex(ValueError, "navigation identity"):
            build.verify(directory)
        with self.assertRaisesRegex(ValueError, "development"):
            build.release_metadata({**self.manifest, "release": None})

    def test_export_normalizes_pages_navigation_and_links_but_preserves_source_and_examples(self):
        (self.root / "docs").mkdir()
        (self.root / "assets").mkdir()
        (self.root / "assets/image.png").write_bytes(b"fixture image")
        (self.root / "source.go").write_text("package fixture\n")
        (self.root / "LICENSE").write_text("Fixture license\n")
        (self.root / "README.md").write_text('# Start\n\n[Next](docs/FIRST_SESSION.md#result)\n![Image](assets/image.png)\n[Source](source.go)\n\n```text\n[Literal](docs/FIRST_SESSION.md)\n```\n')
        (self.root / "docs/FIRST_SESSION.md").write_text("# Result\n\n[Back](../README.md)\n")
        nav = {"sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "README.md"}, {"title": "First session", "path": "docs/FIRST_SESSION.md"}]}]}
        output = self.root / "export"
        output.mkdir()
        with patch.object(build, "ROOT", self.root), patch.object(build, "documents", return_value=[self.root / "README.md", self.root / "docs/FIRST_SESSION.md"]):
            build.populate(output, self.manifest, nav)
        build.verify(output)
        text = (output / "readme.md").read_text()
        self.assertIn("[Next](docs/first-session.md#result)", text)
        self.assertIn("[Literal](docs/FIRST_SESSION.md)", text)
        self.assertIn(f"https://github.com/cavi-ai/secure-agent/blob/{'a' * 40}/source.go", text)
        self.assertEqual((output / "assets/image.png").read_bytes(), b"fixture image")
        self.assertEqual((self.root / "docs/FIRST_SESSION.md").read_text(), "# Result\n\n[Back](../README.md)\n")

    def test_export_rejects_path_collisions_and_nonportable_names(self):
        with patch.object(build, "ROOT", self.root):
            with patch.object(build, "documents", return_value=[self.root / "README.md", self.root / "readme.md"]):
                with self.assertRaisesRegex(ValueError, "collide"):
                    build.populate(self.root / "export", self.manifest, {})
            with self.assertRaisesRegex(ValueError, "portable"):
                build.artifact_path(self.root / "résumé.md")

    def test_artifact_rejects_symbolic_links(self):
        directory = self.artifact()
        (self.root / "outside.txt").write_text("external content")
        (directory / "external.txt").symlink_to(self.root / "outside.txt")
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            build.verify(directory)

    def test_navigation_requires_all_pages_once(self):
        (self.root / "docs").mkdir()
        nav = {"title": "Secure Agent", "version": "1.2.3", "sections": [{"title": "Start", "pages": [{"title": "Overview", "path": "README.md"}]}]}
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
