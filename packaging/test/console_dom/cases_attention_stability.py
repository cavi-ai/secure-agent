"""Attention continuity through the actual console renderer and writes."""
from case_support import html, json, re
from case_types import Case


def run_attention_stability(page):
    for label, size, reduced in [('desktop', (1440, 1000), False), ('narrow', (600, 900), False), ('reduced', (1440, 1000), True)]:
        dom = page.dom('?attentionstability', served=True, window_size=size, reduced_motion=reduced,
                       fixture={'script': 'cases_attention_stability.js'})
        receipt = re.search(r'data-attention-stability-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('middle', 'insertion', 'focus', 'unchanged', 'last', 'interrupted', 'rollback', 'write', 'drawer', 'reading', 'scrolled', 'gutter', 'fits'):
            page.check(f'Attention stability ({label}): {name}', state.get(name) is True, str(state))
        print(f'  geometry ({label}): {state.get("geometry", {})}')


def run_attention_drawer_focus(page):
    for label, size in [('desktop', (1440, 1000)), ('narrow', (600, 900))]:
        dom = page.dom('?attentiondrawerfocus', served=True, window_size=size,
                       fixture={'script': 'cases_attention_drawer_focus.js'})
        receipt = re.search(r'data-attention-drawer-focus-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('more', 'unavailable', 'successor', 'empty'):
            page.check(f'Attention drawer focus ({label}): {name}', state.get(name) is True, str(state))


CASES = (Case('attention_stability', run_attention_stability), Case('attention_drawer_focus', run_attention_drawer_focus))
