"""Worktree disclosure and selection geometry through the real console."""
from case_support import html, json, re
from case_types import Case


def run_worktree_layout(page):
    for width in (320, 390, 559, 560, 561, 719, 720, 721, 1024, 1440, 1280):
        served = width == 1280
        query = f'?worktreelayout&layoutwidth={width}' + ('&layoutchild' if served else '')
        dom = page.dom(query, served=served, window_size=(width if served else 1600, 1000),
                       fixture={'script': 'cases_worktree_layout.js'})
        receipt = re.search(r'data-worktree-layout-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('viewport', 'headerStable', 'fits', 'selectionNodes', 'selectionOpen',
                     'selectionFocus', 'selectionChecked', 'selectionGeometry', 'laneAccent',
                     'rapidDisclosure', 'bulkSelection', 'clearSelection', 'labelSelection',
                     'rejectedSelection', 'busySelection'):
            page.check(f'worktree layout ({width}px): {name}', state.get(name) is True, str(state))


CASES = (Case('worktree_layout', run_worktree_layout),)
