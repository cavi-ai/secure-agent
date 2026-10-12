"""mock_dom.js serves every case; a case family's data, routes and steps go in
its own cases_<family>.js through window.DomTest."""
import os
import unittest

MOCK = os.path.join(os.path.dirname(__file__), "mock_dom.js")
SCENARIO_BRANCHES = 296


class MockScenarioBranchTests(unittest.TestCase):
    def test_mock_scenario_branches_only_decrease(self):
        with open(MOCK) as stream:
            count = stream.read().count("scenarios.has(")
        self.assertLessEqual(count, SCENARIO_BRANCHES,
                             "put the case's data, routes and steps in its cases_<family>.js, not mock_dom.js")
        self.assertEqual(count, SCENARIO_BRANCHES,
                         f"mock_dom.js now has {count} scenario branches; set SCENARIO_BRANCHES = {count}")


if __name__ == "__main__":
    unittest.main()
