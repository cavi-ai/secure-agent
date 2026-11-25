"""The first sidebar control is vertically centered on the page title's first line."""
from case_support import html, json, re
from case_types import Case


def run_masthead_toggle(page):
    for width in (1280, 600):
        dom = page.dom(f'?mastheadtoggle&togglewidth={width}', served=True, window_size=(width, 800),
                       fixture={'script': 'cases_masthead_toggle.js'})
        receipt = re.search(r'data-masthead-toggle="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'Masthead toggle ({width}px): centered on the title within 1px',
                   state.get('viewport') == width and state.get('centered') is True, str(state))


CASES = (Case('masthead_toggle', run_masthead_toggle),)
