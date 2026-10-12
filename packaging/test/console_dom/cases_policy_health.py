"""Independent policy reads, retained records, scoped retries, and reconnect."""
import html
import json
import re
from urllib.parse import parse_qsl

from case_types import Case, Fixture
from fixture_catalog import FIXTURES

HEALTH_FIXTURES = []
for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
    for variant in ('first', 'stale', 'malformed', 'slow', 'reconnect'):
        name, query = f'policy_health_{label}_{variant}', f'?policyhealth={variant}'
        scenarios = tuple(item for key, value in parse_qsl(query.lstrip('?')) for item in (key, f'{key}={value}'))
        FIXTURES[name] = Fixture(query=query, scenarios=scenarios, served=True, window_size=size)
        HEALTH_FIXTURES.append((name, label, variant))


def run_policy_health(page):
    for fixture, label, variant in HEALTH_FIXTURES:
        dom = page.fixture(fixture)
        receipt = re.search(r'data-policy-health-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        names = ('healthy', 'fits', 'focus') + (('pendingSibling', 'usable', 'settled') if variant == 'slow' else
            ('qualified', 'noEmptyClaim', 'readOnly', 'noWrite', 'retryLabel', 'recovered', 'bounded'))
        if variant == 'reconnect':
            names += ('reconnected', 'reloaded')
        for name in names:
            page.check(f'policy health ({label}, {variant}): {name}', state.get(name) is True, str(state))


CASES = (Case('policy_health', run_policy_health, tuple(fixture for fixture, _, _ in HEALTH_FIXTURES)),)
