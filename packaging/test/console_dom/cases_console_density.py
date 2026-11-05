"""Compact rows and persistent sidebar controls through the real console."""
from case_support import html, json, re
from case_types import Case


def run_console_density(page):
    for width in (1440, 1024, 500):
        dom = page.dom('?tab=overview&uisidebars', served=True, window_size=(width, 800),
                       fixture={'script': 'cases_console_density.js'})
        match = re.search(r'data-console-density="([^"]+)"', dom)
        state = json.loads(html.unescape(match.group(1))) if match else {}
        page.check(f'console density ({width}px): actual viewport', state.get('viewport') == width, str(state.get('viewport')))
        for name in ('navigation', 'navigationScroll', 'navigationClose', 'navigationOpen', 'sessionHiddenOnHome',
                     'expandedHeader', 'collapsedHeader', 'restoredHeader', 'sessionHeader',
                     'sessionControl', 'sessionScroll', 'sessionClose', 'sessionOpen',
                     'selectionRetained', 'icons', 'rows', 'fits'):
            page.check(f'console density ({width}px): {name}', state.get(name) is True, str(state))


def run_sidebar_spacing(page):
    for width in (1100, 1099):
        dom = page.dom('?tab=overview&uisidebars', served=True, window_size=(width, 800),
                       fixture={'script': 'cases_console_density.js'})
        match = re.search(r'data-console-density="([^"]+)"', dom)
        state = json.loads(html.unescape(match.group(1))) if match else {}
        page.check(f'sidebar spacing ({width}px): actual viewport', state.get('viewport') == width, str(state))
        for name in ('expandedHeader', 'collapsedHeader', 'restoredHeader', 'sessionHeader', 'fits'):
            page.check(f'sidebar spacing ({width}px): {name}', state.get(name) is True, str(state))


CASES = (Case('console_density', run_console_density), Case('sidebar_spacing', run_sidebar_spacing))
