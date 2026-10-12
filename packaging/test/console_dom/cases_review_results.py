"""Retained review-result interactions at desktop and narrow widths."""
import html
import json
import re

from case_types import Case, Fixture
import payload_cases
from fixture_catalog import FIXTURES

REVIEW_FIXTURES = []
for label, size in [('desktop', (1280, 800)), ('narrow', (375, 800))]:
    for action in ('acknowledge', 'close_reported', 'expect'):
        name = f'review_result_{label}_{action}'
        scenarios = (f'reviewresult={action}', 'reviewresult')
        query = '?reviewresult=' + action
        if action == 'acknowledge':
            scenarios += ('dismissresult',)
            query += '&dismissresult'
        elif action == 'expect':
            scenarios += ('resultrevoke',)
            query += '&resultrevoke'
        FIXTURES[name] = Fixture(query=query, scenarios=scenarios,
                                 window_size=size, served=True,
                                 payload=payload_cases.scoped_review)
        REVIEW_FIXTURES.append((name, label, action))


def run_review_results(page):
    for fixture, label, action in REVIEW_FIXTURES:
        dom = page.fixture(fixture)
        receipt = re.search(r'data-review-result-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        names = ('queueCleared', 'retained', 'label', 'fits', 'evidence', 'readOnly',
                 'evidenceEntry', 'evidenceReturn', 'permissionEntry')
        if action == 'acknowledge':
            names += ('dismissed',)
        elif action == 'expect':
            names += ('permissionDetail', 'permissionScope', 'permissionFits',
                      'permissionCancelled', 'permissionRevoked', 'permissionReturn')
        for name in names:
            page.check(f'review result ({label}, {action}): {name}',
                       state.get(name) is True, str(state))


CASES = (Case('review_results', run_review_results,
              tuple(fixture for fixture, _, _ in REVIEW_FIXTURES)),)
