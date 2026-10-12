#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import plistlib
import unittest

spec = importlib.util.spec_from_file_location(
    "check_menu_bar", Path(__file__).resolve().parents[1] / "check_menu_bar.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

APP_ID = "com.example.agent"
APP = {"bundle": {"_0": APP_ID}}
PARENT = {"bundle": {"_0": "com.example.launcher"}}


def preferences(records):
    return {"trackedApplications": plistlib.dumps(records, fmt=plistlib.FMT_BINARY)}


class MenuBarTrackingTests(unittest.TestCase):
    def test_foreign_disabled_record_blocks_an_enabled_app(self):
        state = preferences([
            APP, {"isAllowed": True, "menuItemLocations": [APP]},
            PARENT, {"isAllowed": False, "menuItemLocations": [PARENT, APP]},
        ])
        self.assertEqual(checker.blocked_owners(state, APP_ID), [PARENT])

    def test_removing_foreign_reference_clears_the_block(self):
        state = preferences([
            APP, {"isAllowed": True, "menuItemLocations": [APP]},
            PARENT, {"isAllowed": False, "menuItemLocations": [PARENT]},
        ])
        self.assertEqual(checker.blocked_owners(state, APP_ID), [])

    def test_own_disabled_record_is_reported(self):
        state = preferences([APP, {"isAllowed": False, "menuItemLocations": [APP]}])
        self.assertEqual(checker.blocked_owners(state, APP_ID), [APP])

    def test_allowed_foreign_record_does_not_block(self):
        state = preferences([PARENT, {"isAllowed": True, "menuItemLocations": [APP]}])
        self.assertEqual(checker.blocked_owners(state, APP_ID), [])

    def test_unknown_format_is_not_reported_as_healthy(self):
        for records in [[APP], [APP, {"menuItemLocations": [APP]}]]:
            with self.subTest(records=records):
                with self.assertRaises(ValueError):
                    checker.blocked_owners(preferences(records), APP_ID)
        with self.assertRaises(ValueError):
            checker.blocked_owners({}, APP_ID)
        with self.assertRaises(ValueError):
            checker.blocked_owners([], APP_ID)


if __name__ == "__main__":
    unittest.main()
