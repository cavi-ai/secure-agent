"""Incident summaries stay in the inspector while queue cards remain readable."""
from case_support import html, json, re
from case_types import Case


def run_incident_cards(page):
    for width, theme in ((500, 'dark'), (1280, 'dark'), (1280, 'light')):
        dom = page.dom(f'?tab=home&theme={theme}', served=True, window_size=(width, 900),
                       fixture={'script': 'cases_incident_cards.js'})
        receipt = re.search(r'data-incident-cards="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        for name in ('count', 'compact', 'title', 'evidence', 'risk', 'actions', 'focus', 'fits', 'inspector'):
            page.check(f'Incident cards ({width}px, {theme}): {name}', state.get(name) is True, str(state))


CASES = (Case('incident_cards', run_incident_cards),)
