"""Long telemetry and error strings stay within console chrome and side panes."""
from case_support import html, json, re
from case_types import Case


def run_frontend_bounds(page):
    for width in (320, 360, 390, 428, 768, 1099, 1280, 1600):
        served = width in (1280, 1600)
        query = f'?frontendbounds&boundswidth={width}' + ('&boundschild' if served else '')
        dom = page.dom(query, served=served, window_size=(width if served else 1600, 1000),
                       fixture={'script': 'cases_frontend_bounds.js'})
        receipt = re.search(r'data-frontend-bounds="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'Frontend bounds ({width}px): actual viewport', state.get('viewport') == width, str(state))
        for name in ('bounded', 'named', 'skillTitle', 'drawerClose', 'confirmTitle', 'confirmCancel', 'cancelled', 'errorToast', 'removalToast', 'pageFits'):
            page.check(f'Frontend bounds ({width}px): {name}', state.get(name) is True, str(state))


CASES = (Case('frontend_bounds', run_frontend_bounds),)
