"""Exercise release source selection and signed-bundle metadata checks."""
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'packaging/lib/release_source.sh'
BUNDLE = ROOT / 'packaging/lib/release_bundle.py'
RELEASE = ROOT / 'packaging/lib/release.sh'


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'tag.gpgSign', 'false')
        self.git('commit', '--allow-empty', '-qm', 'first')
        self.old = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v1.2.3')
        self.git('commit', '--allow-empty', '-qm', 'second')
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, text=True).strip()

    def resolve(self, tag, pin, event='', event_sha=None):
        env = dict(os.environ, INPUT_TAG=tag, EXPECTED_SHA=pin, EVENT_TAG=event, GITHUB_SHA=event_sha or self.head)
        return subprocess.run(['bash', str(SOURCE)], cwd=self.repo, env=env, text=True, capture_output=True)

    def test_manual_tag_requires_exact_full_pin(self):
        for pin in ('', self.head, self.old[:12], 'x' * 40):
            with self.subTest(pin=pin):
                self.assertNotEqual(self.resolve('v1.2.3', pin).returncode, 0)
        result = self.resolve('v1.2.3', self.old)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), self.old)

    def test_moved_annotated_tag_rejects_prepared_commit(self):
        self.git('tag', '-fa', 'v1.2.3', '-m', 'moved', self.head)
        self.assertNotEqual(self.resolve('v1.2.3', self.old).returncode, 0)
        self.assertNotEqual(self.resolve('', '', 'v1.2.3', self.old).returncode, 0)
        self.assertEqual(self.resolve('v1.2.3', self.head).stdout.strip(), self.head)

    def test_source_only_and_release_event(self):
        self.assertEqual(self.resolve('', '').stdout.strip(), self.head)
        self.assertNotEqual(self.resolve('', self.head).returncode, 0)
        self.assertEqual(self.resolve('', '', 'v1.2.3', self.old).stdout.strip(), self.old)
        self.assertNotEqual(self.resolve('', '', 'v1.2.3', self.head).returncode, 0)
        self.assertNotEqual(self.resolve('v1.2.4', self.old).returncode, 0)
        self.assertNotEqual(self.resolve('', '', 'invalid').returncode, 0)

    def test_stamp_requires_clean_worktree(self):
        def stamp():
            return subprocess.check_output(['bash', '-c', 'source "$1"; release_source_revision',
                                            'bash', str(RELEASE)], cwd=self.repo, text=True).strip()
        self.assertEqual(stamp(), self.head)
        path = self.repo / 'new-file'
        path.write_text('untracked')
        self.assertEqual(stamp(), '')
        self.git('add', 'new-file')
        self.assertEqual(stamp(), '')
        self.git('commit', '-qm', 'tracked')
        path.write_text('changed')
        self.assertEqual(stamp(), '')

    def test_bundle_version_and_revision(self):
        plist = self.repo / 'Info.plist'
        def check(version, revision):
            contents = {'CFBundleShortVersionString': version}
            if revision is not None:
                contents['SecureAgentSourceRevision'] = revision
            plist.write_bytes(plistlib.dumps(contents))
            return subprocess.run(['python3', str(BUNDLE), str(plist), 'v1.2.3', self.old], capture_output=True, text=True)
        self.assertEqual(check('1.2.3', self.old).returncode, 0)
        for version, revision in [('1.2.3', self.head), ('1.2.3', None), ('1.2.4', self.old)]:
            with self.subTest(version=version, revision=revision):
                self.assertNotEqual(check(version, revision).returncode, 0)


if __name__ == '__main__':
    unittest.main()
