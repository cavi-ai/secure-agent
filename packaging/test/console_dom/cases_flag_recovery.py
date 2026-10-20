"""Retained finding actions and unavailable evidence recovery."""
from case_support import html, json, re
from case_types import Case


def run_flag_recovery(page):
    for label, size in [('desktop', (1440, 1000)), ('phone', (390, 844))]:
        dom = page.dom('?flagrecovery', served=True, window_size=size,
                       fixture={'script': 'cases_flag_recovery.js'})
        receipt = re.search(r'data-flag-recovery-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('previewEvidence', 'previewLabel', 'queueActions', 'retainedEvidence', 'missing', 'unavailable', 'retry', 'rejected', 'dismissed', 'fits'):
            page.check(f'flag recovery ({label}): {name}', state.get(name) is True, str(state))


CASES = (Case('flag_recovery', run_flag_recovery),)
