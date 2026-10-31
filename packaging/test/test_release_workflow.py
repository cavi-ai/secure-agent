"""Check the release validation job graph against GitHub's skip rule: a job
whose needs include a skipped job is skipped too unless it has its own `if`."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release-validation.yml"


def jobs(text):
    """Each job's needs and whether it declares its own `if`."""
    out, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            in_jobs = line.rstrip() == "jobs:"
            current = None
            continue
        if not in_jobs:
            continue
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            current = out.setdefault(header.group(1), {"needs": [], "if": False})
            continue
        if current is None:
            continue
        needs = re.match(r"^    needs:\s*(.+?)\s*$", line)
        if needs:
            current["needs"] = [n.strip() for n in needs.group(1).strip("[]").split(",") if n.strip()]
        elif re.match(r"^    if:", line):
            current["if"] = True
    return out


def skipped_with_a_conditional_job(graph):
    """Jobs without their own `if` that need, directly or through other jobs,
    a job that has one."""
    def ancestors(name, seen):
        for parent in graph[name]["needs"]:
            if parent not in seen:
                seen.add(parent)
                ancestors(parent, seen)
        return seen
    return sorted(name for name, job in graph.items()
                  if not job["if"] and any(graph[a]["if"] for a in ancestors(name, set())))


class ReleaseWorkflowTests(unittest.TestCase):
    def test_parses_the_release_jobs(self):
        graph = jobs(WORKFLOW.read_text())
        self.assertEqual(graph["promote"]["needs"], ["prepare", "macos-go", "menubar", "e2e", "dmg"])
        self.assertTrue(graph["build"]["if"])

    def test_no_job_is_skipped_with_a_skipped_ancestor(self):
        self.assertEqual(skipped_with_a_conditional_job(jobs(WORKFLOW.read_text())), [])


if __name__ == "__main__":
    unittest.main()
