"""Contract tests for the optional shell classifier customization tool (no weights)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import customize


POLICY = Path(__file__).resolve().parents[2] / "daemon/internal/shellreview/policy.json"


def sample(split, label, family=None, command=None):
    return {"id": f"{split}-{label}", "split": split, "family": family or f"{split}-{label}",
            "label": label, "command": command or f"printf {split}-{label}", "cwd": "/workspace/project"}


class DatasetContract(unittest.TestCase):
    def setUp(self):
        self.rows = [sample(s, k) for s in ("train", "development", "test")
                     for k in ("routine", "review", "unknown")]

    def test_all_splits_and_labels_are_required(self):
        customize.validate_rows(self.rows)
        for rows in (self.rows[:-1], self.rows + [copy.deepcopy(self.rows[0])]):
            with self.assertRaises(ValueError):
                customize.validate_rows(rows)

    def test_command_and_family_leakage_are_rejected(self):
        for field in ("command", "family"):
            rows = copy.deepcopy(self.rows)
            rows[3][field] = rows[0][field]
            with self.assertRaises(ValueError):
                customize.validate_rows(rows)

    def test_unknown_fields_bad_labels_and_control_bytes_are_rejected(self):
        for update in ({"label": "safe"}, {"split": "dev"}, {"command": "a\x00b"},
                       {"command": "x" * 8193}, {"cwd": "x" * 4097}, {"unexpected": True}):
            rows = copy.deepcopy(self.rows)
            rows[0].update(update)
            with self.assertRaises(ValueError):
                customize.validate_rows(rows)

    def test_policy_request_uses_production_order_and_no_labels(self):
        policy = customize.load_policy(POLICY)
        request = customize.request_for(self.rows[0], policy)
        self.assertEqual(request["state"], "Working directory: /workspace/project\nShell command:\nprintf train-routine")
        question = request["questions"]["risk"]
        self.assertEqual(list(question["criteria"]), ["review", "routine", "unknown"])
        self.assertNotIn("label", question)
        self.assertEqual(question["instructions"], policy["instructions"])

    def test_manifest_checksums_prevent_dataset_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "suite.json"
            path.write_text(json.dumps({"version": 1, "rows": self.rows}))
            customize.freeze(path, POLICY, root / "manifest.json")
            customize.load_suite(path, POLICY, root / "manifest.json")
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                customize.load_suite(path, POLICY, root / "manifest.json")


class MetricsContract(unittest.TestCase):
    def test_dangerous_routine_is_separate_from_abstention_and_label_accuracy(self):
        rows = [sample("test", k) for k in ("routine", "review", "unknown")]
        probabilities = [{"routine": .91, "review": .05, "unknown": .04},
                         {"routine": .94, "review": .04, "unknown": .02},
                         {"routine": .89, "review": .05, "unknown": .06}]
        result = customize.summarize(rows, probabilities)
        self.assertEqual(result["correct"], 1)
        self.assertEqual(result["false_routine"], 1)
        self.assertEqual(result["routine_allowed"], 1)
        self.assertEqual(result["abstained"], 1)
        self.assertEqual(result["by_label"]["unknown"]["false_routine"], 0)

    def test_serving_rounding_is_applied_before_gate_threshold(self):
        result = customize.summarize([sample("test", "review")],
                                     [{"routine": .896, "review": .064, "unknown": .04}])
        self.assertEqual(result["false_routine"], 1)

    def test_missing_or_invalid_predictions_cannot_produce_partial_metrics(self):
        row = sample("test", "routine")
        for probabilities in ([], [{"routine": 1}],
                              [{"routine": float("nan"), "review": 0, "unknown": 0}],
                              [{"routine": .9, "review": .9, "unknown": .9}]):
            with self.assertRaises(ValueError):
                customize.summarize([row], probabilities)

    def test_selection_prioritizes_false_routine_over_label_accuracy(self):
        unsafe = {"false_routine": 1, "correct": 99, "routine_allowed": 49}
        conservative = {"false_routine": 0, "correct": 98, "routine_allowed": 48}
        self.assertGreater(customize.selection_key(conservative), customize.selection_key(unsafe))

    def test_known_false_allows_reject_a_candidate_even_with_better_accuracy(self):
        baseline = {"false_routine": 2, "correct": 6, "routine_allowed": 3, "n": 10}
        candidate = {"false_routine": 1, "correct": 9, "routine_allowed": 5, "n": 10}
        self.assertEqual(customize.assessment(baseline, candidate), ["non_routine_commands_allowed"])
        candidate["false_routine"] = 0
        self.assertEqual(customize.assessment(baseline, candidate), [])
        candidate["routine_allowed"] = 2
        self.assertEqual(customize.assessment(baseline, candidate), ["routine_coverage_regressed"])
        candidate["correct"] = 5
        self.assertIn("label_accuracy_regressed", customize.assessment(baseline, candidate))

    def test_reports_with_different_sample_counts_are_rejected(self):
        with self.assertRaises(ValueError):
            customize.assessment({"n": 10}, {"n": 9})


if __name__ == "__main__":
    unittest.main()
