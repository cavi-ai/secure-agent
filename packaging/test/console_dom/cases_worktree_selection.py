"""Bulk worktree selection through the real console and confirmation dialog."""
import html
import json
import re

from case_types import Case, Fixture
from fixture_catalog import FIXTURES

SELECTION_FIXTURES = []
ASYNC_FAILURE_FIXTURES = []
for label, size in [('desktop', (1280, 900)), ('narrow', (375, 850))]:
    for mode in ('review', 'execute', 'failure', 'asyncfailure'):
        name = f'worktree_selection_{label}_{mode}'
        FIXTURES[name] = Fixture(
            query=f'?tab=worktrees&worktreeselection={mode}',
            scenarios=('tab', 'tab=worktrees', f'worktreeselection={mode}'),
            window_size=size, served=True, script='cases_worktree_selection.js',
        )
        target = ASYNC_FAILURE_FIXTURES if mode == 'asyncfailure' else SELECTION_FIXTURES
        target.append((name, label, mode))


def check_worktree_selection(page, fixtures):
    for fixture, label, mode in fixtures:
        dom = page.fixture(fixture)
        receipt = re.search(r'data-worktree-selection-probe="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        checks = [
            'blocked', 'marked', 'keyboardFocus', 'crossRepo', 'filterRetains',
            'clear', 'selectVisible', 'cancelled', 'reviewPaths', 'reviewActions',
            'reviewRisks', 'partialSize', 'fits', 'dialogFits',
        ]
        if mode != 'review':
            checks += ['oneConfirmation', 'routes', 'payload', 'noReplay']
            checks += ['failedRetained', 'failureNamed'] if mode in ('failure', 'asyncfailure') else ['selectionCleared', 'trashedGone']
        for check in checks:
            page.check(f'worktree selection ({label}, {mode}): {check}',
                       state.get(check) is True, str(state))


def run_worktree_selection(page):
    check_worktree_selection(page, SELECTION_FIXTURES)


def run_worktree_selection_async_failure(page):
    check_worktree_selection(page, ASYNC_FAILURE_FIXTURES)


CASES = (
    Case('worktree_selection', run_worktree_selection,
         tuple(fixture for fixture, _, _ in SELECTION_FIXTURES)),
    Case('worktree_selection_async_failure', run_worktree_selection_async_failure,
         tuple(fixture for fixture, _, _ in ASYNC_FAILURE_FIXTURES)),
)
