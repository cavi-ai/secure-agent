"""A stale expectation choice explains incomplete activity identity."""
from case_support import html, json, re
from case_types import Case


def run_egress_expectation(page):
    dom = page.dom('?expectationidentity', served=True,
                   fixture={'script': 'cases_egress_expectation.js'})
    match = re.search(r'data-egress-expectation="([^"]+)"', dom)
    probe = json.loads(html.unescape(match.group(1))) if match else {}
    for name in ('offered', 'feedback', 'noWrite', 'noConfirmation'):
        page.check(f'Expectation identity: {name}', probe.get(name) is True, str(probe))


CASES = (Case('egress_expectation_identity', run_egress_expectation),)
