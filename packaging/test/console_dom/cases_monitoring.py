"""Monitoring navigation, observations and stale evidence behavior."""
from case_support import html, json, re
from case_types import Case


def run_monitoring(page):
    for label, size in [('desktop', (1440, 1024)), ('phone', (390, 844))]:
        dom = page.dom('?monitoring', served=True, window_size=size, fixture={'script': 'cases_monitoring.js'})
        receipt = re.search(r'data-monitoring-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('primary', 'list', 'paths', 'reading', 'unsupported', 'search', 'unlinked', 'issues', 'stale', 'handoff', 'removed', 'fits'):
            page.check(f'Monitoring ({label}): {name}', state.get(name) is True, str(state))


CASES = (Case('monitoring', run_monitoring),)
