"""Inspecting a saved egress expectation from Protection traffic."""
import html
import json

from case_support import pre
from case_types import Case, Fixture
from fixture_catalog import FIXTURES

FOUND = ('rules', 'selected', 'anyTarget', 'nonDestructiveFocus', 'rationale', 'refreshNode', 'refreshFocus',
         'returned', 'manualCleared', 'noWrites')
# An absent or unreadable rule is never replaced by a same-host rule.
UNAVAILABLE = {'rules': True, 'selected': False, 'anyTarget': False, 'returned': True, 'manualCleared': True,
               'noWrites': True}

CONTEXT_FIXTURES = []
# The checked-read variant's first read has no rules, so selecting the rule
# proves the read happened.
for variant, scenario, expected in [('known rule', None, dict.fromkeys(FOUND, True)),
                                    ('rule found by a checked read', 'contextread', dict.fromkeys(FOUND, True)),
                                    ('missing rule', 'contextmissing', UNAVAILABLE),
                                    ('failed read', 'contextfail', UNAVAILABLE)]:
    scenarios = ('protectioncontextprobe',) + ((scenario,) if scenario else ())
    name = 'protection_context_' + variant.replace(' ', '_')
    FIXTURES[name] = Fixture(query='?' + '&'.join(scenarios), scenarios=scenarios, served=True)
    CONTEXT_FIXTURES.append((name, variant, expected))


def run_protection_context(page):
    for fixture, variant, expected in CONTEXT_FIXTURES:
        raw = html.unescape(pre(page.fixture(fixture), 'protection-context-probe'))
        try:
            probe = json.loads(raw)
        except (ValueError, TypeError):
            probe = {}
        for field, value in expected.items():
            page.check(f'protection context ({variant}): {field}', probe.get(field) is value, raw)


CASES = (Case('protection_context', run_protection_context, tuple(fixture for fixture, _, _ in CONTEXT_FIXTURES)),)
