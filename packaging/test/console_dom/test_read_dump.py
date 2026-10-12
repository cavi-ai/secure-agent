"""Chrome may stay alive after --dump-dom prints the document."""
import subprocess
import sys
import time
import unittest

from run_dom_tests import read_dump


def fake_chrome(script):
    return subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE)


class ReadDumpTests(unittest.TestCase):
    def test_complete_document_returns_while_chrome_lingers(self):
        proc = fake_chrome("import time; print('<html><body>ok</body></html>', flush=True); time.sleep(60)")
        started = time.monotonic()
        out, complete = read_dump(proc, "fixture", timeout=30)
        self.assertTrue(complete)
        self.assertIn("<body>ok</body>", out)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIsNotNone(proc.poll(), "lingering Chrome was not stopped")

    def test_partial_document_is_incomplete(self):
        proc = fake_chrome("import sys; print('<html><body>', flush=True); sys.exit(3)")
        out, complete = read_dump(proc, "fixture", timeout=30)
        self.assertFalse(complete)
        self.assertEqual(proc.returncode, 3)

    def test_unfinished_document_times_out(self):
        proc = fake_chrome("import time; print('<html>', flush=True); time.sleep(60)")
        with self.assertRaises(SystemExit):
            read_dump(proc, "fixture", timeout=1)
        self.assertIsNotNone(proc.poll())


if __name__ == "__main__":
    unittest.main()
