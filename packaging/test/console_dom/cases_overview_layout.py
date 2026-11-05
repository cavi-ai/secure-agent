"""Stable overview geometry and live row updates through real console actions."""
from case_support import html, json, re
from case_types import Case


def run_overview_layout(page):
    for width in (1600, 900, 500):
        dom = page.dom('?overviewlayout', served=True, window_size=(width, 1000),
                       fixture={'script': 'cases_overview_layout.js'})
        receipt = re.search(r'data-overview-layout="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'Overview layout ({width}px): actual viewport', state.get('viewport', {}).get('width') == width, str(state.get('viewport')))
        for name in ('dismiss', 'empty', 'quietDismissal', 'order', 'focus', 'liveTime', 'updates', 'refresh',
                     'workspace', 'bounded', 'breakdown', 'still', 'motion', 'fits'):
            page.check(f'Overview layout ({width}px): {name}', state.get(name) is True, str(state))


CASES = (Case('overview_layout', run_overview_layout),)
