"""Expected exception removal receipts and recovery at desktop and phone widths."""
import html
import json
import re
from urllib.parse import parse_qsl

from case_types import Case, Fixture
from fixture_catalog import FIXTURES

REMOVAL_FIXTURES = []
for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
    for variant, query in [('pattern', '?expectedremove=pattern'), ('file', '?expectedremove=file'),
                           ('uncertain', '?expectedremove=pattern&removaluncertain'),
                           ('read failure', '?expectedremove=pattern&removalreadfail'),
                           ('invalid', '?expectedremove=pattern&removalinvalid')]:
        name = f'expected_removal_{label}_{variant.replace(" ", "_")}'
        scenarios = tuple(item for key, value in parse_qsl(query.lstrip('?'), keep_blank_values=True)
                          for item in ((key, f'{key}={value}') if value else (key,)))
        FIXTURES[name] = Fixture(query=query, scenarios=scenarios, window_size=size, served=True)
        REMOVAL_FIXTURES.append((name, label, variant))


def run_expected_removal(page):
    for fixture, label, variant in REMOVAL_FIXTURES:
        dom = page.fixture(fixture)
        receipt = re.search(r'data-expected-removal-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        names = ('unavailable', 'noWrite', 'fits') if variant == 'invalid' else (
            'label', 'target', 'scope', 'consequence', 'cancelled', 'oneWrite', 'fits',
            *(('uncertain', 'noReplay', 'refreshed', 'authoritative') if variant == 'uncertain' else ('saved', 'remaining', 'feedback')),
            *(('retained',) if variant == 'read failure' else ()))
        for name in names:
            page.check(f'exception removal ({label}, {variant}): {name}', state.get(name) is True, str(state))


CASES = (Case('expected_removal', run_expected_removal,
              tuple(fixture for fixture, _, _ in REMOVAL_FIXTURES)),)
