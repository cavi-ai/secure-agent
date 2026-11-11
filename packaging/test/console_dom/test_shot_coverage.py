"""Every top-level console tab has a mock-rendered screenshot in both themes."""
import os
import re
import unittest
from urllib.parse import parse_qs

from run_dom_tests import SHOTS, WEB_DIST


def console_routes():
    with open(os.path.join(WEB_DIST, "lib.js")) as stream:
        source = stream.read()
    tabs = re.search(r"const CONSOLE_TABS = \[([^\]]*)\]", source).group(1)
    aliases = re.search(r"const TAB_ALIASES = \{(.*?)\n\};", source, re.S).group(1)
    return re.findall(r"'(\w+)'", tabs), dict(re.findall(r"(\w+): \{ tab: '(\w+)'", aliases))


class ShotCoverageTests(unittest.TestCase):
    def test_every_console_tab_has_a_dark_and_light_shot(self):
        tabs, aliases = console_routes()
        covered = {}
        for _, query, themes in SHOTS:
            head = parse_qs(query.lstrip("?"), keep_blank_values=True)["tab"][0].split("/")[0]
            covered.setdefault(aliases.get(head, head), set()).update(themes)
        missing = {tab: sorted({"dark", "light"} - covered.get(tab, set())) for tab in tabs}
        self.assertEqual({tab: themes for tab, themes in missing.items() if themes}, {})


if __name__ == "__main__":
    unittest.main()
