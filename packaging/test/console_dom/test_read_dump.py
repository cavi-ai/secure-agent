"""Exercise Chrome dump handling with a real child process and pipe."""

import subprocess
import sys
import time
import unittest

from run_dom_tests import read_dump


class ReadDumpTests(unittest.TestCase):
    def start_child(self, script):
        proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE)

        def cleanup():
            proc.kill()
            proc.wait()
            proc.stdout.close()

        self.addCleanup(cleanup)
        return proc

    def test_complete_document_returns_while_chrome_lingers(self):
        proc = self.start_child("import time; print('<html><body>ok</body></html>', flush=True); time.sleep(60)")
        started = time.monotonic()
        out, complete = read_dump(proc, "fixture", timeout=30)
        self.assertTrue(complete)
        self.assertIn("<body>ok</body>", out)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIsNotNone(proc.poll(), "lingering Chrome was not stopped")

    def test_partial_document_is_incomplete(self):
        proc = self.start_child("import sys; print('<html><body>', flush=True); sys.exit(3)")
        out, complete = read_dump(proc, "fixture", timeout=30)
        self.assertFalse(complete)
        self.assertIn("<html><body>", out)
        self.assertEqual(proc.returncode, 3)

    def test_unfinished_document_times_out(self):
        proc = self.start_child("import time; print('<html>', flush=True); time.sleep(60)")
        with self.assertRaisesRegex(SystemExit, "timed out after 1s: fixture"):
            read_dump(proc, "fixture", timeout=1)
        self.assertIsNotNone(proc.poll(), "timed-out Chrome was not stopped")
