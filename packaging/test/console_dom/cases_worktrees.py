"""Console worktrees cases."""
from case_support import html, json, re, HTMLParser, dom_query, starts_with, payload_cases, pre, log_rows, PolicyRowCounter
from case_types import Case

def run_worktrees(page):
    check = page.check
    dom_memfam = page.fixture('dom_memfam')
    dom_wt = page.fixture('dom_wt')
    dom_wtdiscuss = page.fixture('dom_wtdiscuss')
    dom_wtdiscussoff = page.fixture('dom_wtdiscussoff')
    dom_wtdockcycle = page.fixture('dom_wtdockcycle')
    dom_wtrefresh = page.fixture('dom_wtrefresh')
    dom_wtreview = page.fixture('dom_wtreview')
    dom_wtreviewtrash = page.fixture('dom_wtreviewtrash')
    dom_wtsizing = page.fixture('dom_wtsizing')
    mem_bars = dom_memfam.split('id="chart-memory"', 1)[1].split('</section>', 1)[0].split('class="hbar-row"')[1:]
    mem_infra = sum(('class="hbar-sub">infra<' in b for b in mem_bars))

    def wt_block(dom_text):
        return dom_text.split('id="worktrees-container"', 1)[-1].split('data-action="clutter-rescan"', 1)[0]
    wt = wt_block(dom_wt)
    wt_rows = len(dom_query(wt).find_all(None, {'class': 'wt-row'}))
    wt_remove = len(dom_query(wt).find_all(None, {'data-action': 'worktree-remove'}))
    wt_prune = len(dom_query(wt).find_all(None, {'data-action': 'worktree-prune'}))
    check(
        'worktrees: the System tab opens and renders a row per non-main worktree with its state',
        (
            dom_query(dom_wt).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
            and not dom_query(dom_wt).has(None, {'data-subtab': 'worktrees'})
            and [b.attrs.get('data-tab') for b in dom_query(dom_wt).find_all(None, {'class': 'tab-btn'})] == ['home', 'sessions', 'monitoring', 'protection', 'system', 'agent']
            and wt_rows == 4
            and all((f'class="wt-row wt-{s}"' in wt for s in ('remove', 'review', 'keep', 'prune')))
            and 'main worktree of the repository' not in wt
        ),
        f'rows={wt_rows}',
    )
    check(
        'worktrees: git Remove only on the remove row, Prune only on the prune row',
        (
            wt_remove == 1
            and wt_prune == 1
            and dom_query(wt).has(None, {'data-action': 'worktree-remove', 'data-path': '/Users/dev/workspace/api-service/.worktrees/done'})
        ),
        f'remove={wt_remove} prune={wt_prune}',
    )
    check(
        'worktrees: reasons render as text, paths inside the repo read relative',
        (
            '&lt;b&gt;not bold&lt;/b&gt;' in wt
            and '<b>not bold</b>' not in wt
            and '<button type="button" class="wt-path" data-action="copy-path" data-path="/Users/dev/workspace/api-service/.worktrees/done" title="/Users/dev/workspace/api-service/.worktrees/done — click to copy">.worktrees/done</button>' in wt
        ),
    )
    check(
        'worktrees: reasons are tags toned by kind, and the agent chip replaces the agent reason',
        (
            '<li class="wt-reason wt-reason-keep">2 uncommitted changes</li>' in wt
            and '<li class="wt-reason wt-reason-review">ignored files that only live here: .tmp/ (3 files, 1.2 MB)</li>' in wt
            and '<li class="wt-reason wt-reason-safe">merged into origin/main (squash)</li>' in wt
            and '<li class="wt-reason wt-reason-info">directory is gone; git still lists it</li>' in wt
            and 'an agent session is live here</li>' not in wt
            and '<div class="wt-title"><span class="wt-branch">(detached)</span><span class="wt-agent-live"' in wt
        ),
    )
    check(
        'worktrees: state pills carry counts and the summary line reads the scan',
        (
            'data-state="" aria-pressed="true">All <b>4</b></button>' in dom_wt
            and 'data-state="remove" aria-pressed="false">Remove <b>1</b></button>' in dom_wt
            and (
                '1 repo · 4 worktrees · stale after 14 idle days · scanned in 4.2s' in dom_query(dom_wt).text
                or dom_query(dom_wt).has(None, {'title': lambda value: '1 repo · 4 worktrees · stale after 14 idle days · scanned in 4.2s' in (value or '')})
            )
        ),
    )
    check(
        'worktrees: the advisor note renders escaped under its row and ends in Discuss; Ask advisor sits on review and keep rows only',
        (
            '<p class="wt-advice"><b>Advisor: review</b> 60% · &lt;i&gt;look&lt;/i&gt; at .tmp before removing <button type="button" class="link-btn" data-action="worktree-discuss" data-path="/Users/dev/workspace/api-service/.worktrees/evidence">Discuss</button></p>' in wt
            and len(dom_query(wt).find_all(None, {'data-action': 'worktree-advise'})) == 2
        ),
    )
    check(
        'worktrees: Discuss sits on the remove, review and keep rows and the note, not on the prune row',
        (
            len(dom_query(wt).find_all(None, {'data-action': 'worktree-discuss'})) == 4
            and not dom_query(wt).has(None, {'data-action': 'worktree-discuss', 'data-path': '/Users/dev/workspace/api-service/.worktrees/gone'})
        ),
    )
    check(
        'worktrees: Ask <harness> appears only for the active agent; no review drawer button remains',
        (
            len(dom_query(wt).find_all(None, {'data-action': 'worktree-ask'})) == 1
            and dom_query(wt).has(None, {'class': 'btn btn-primary btn-sm', 'data-action': 'worktree-ask'})
            and '>Ask codex</button>' in wt
            and 'Ask the agent' not in wt
            and not dom_query(wt).has(None, {'data-action': 'worktree-review'})
            and '<p class="wt-ask wt-ask-answered"><b>Asked claude:</b> pr — https://github.com/o/r/pull/9 (session $0.21)</p>' in wt
        ),
    )
    check(
        'worktrees: review and keep rows carry Remove; the row with a live agent session is disabled and says why',
        (
            len(dom_query(wt).find_all(None, {'data-action': 'worktree-review-trash'})) == 1
            and dom_query(wt).has(None, {'data-action': 'worktree-review-trash', 'data-path': '/Users/dev/workspace/api-service/.worktrees/evidence'})
            and wt.count('>Remove</button>') == 2
            and wt.count('>Remove…</button>') == 1
            and 'disabled="" title="Cannot remove: an agent session is live here">Remove</button>' in wt
        ),
    )
    check(
        'worktrees: Remove has three looks: solid red when confirmed safe, amber outline when not confirmed, greyed when blocked; a legend explains them',
        (
            '<button type="button" class="btn btn-danger-solid btn-sm" data-action="worktree-remove" data-path="/Users/dev/workspace/api-service/.worktrees/done" data-branch="feat/done" title="Safe to remove: merged into origin/main (squash)">Remove</button>' in wt
            and dom_query(wt).has('button', {'type': 'button', 'class': 'btn btn-warn-outline btn-sm', 'data-action': 'worktree-review-trash', 'data-path': '/Users/dev/workspace/api-service/.worktrees/evidence'})
            and dom_query(wt).has(None, {'title': starts_with('Not confirmed safe: ignored files that only live here: .tmp/ (3 files, 1.2 MB); ')})
            and 'not bold' in wt
            and '. Moves the folder to the Trash; the branch stays in git">Remove…</button>' in wt
            and '<button type="button" class="btn btn-sm" disabled="" title="Cannot remove: an agent session is live here">Remove</button>' in wt
            and 'btn btn-danger btn-sm" data-action="worktree-review-trash"' not in wt
            and 'btn btn-danger btn-sm" disabled' not in wt
        ),
    )
    check(
        'worktrees: the legend under the summary names the three Remove looks and is visible with a scan',
        (
            '<p class="wt-legend" id="worktrees-legend">Remove: confirmed safe · Remove…: not confirmed, goes to the Trash · greyed: blocked</p>' in dom_wt
            and '<p class="wt-legend" id="worktrees-legend" hidden' not in dom_wt
        ),
    )
    check(
        'worktrees: the repository group offers Ask advisor about all and Discuss all beside Hide repo, counted over every row',
        (
            len(dom_query(wt).find_all(None, {'data-action': 'worktree-advise-all', 'data-repo': '/Users/dev/workspace/api-service'})) == 1
            and len(dom_query(wt).find_all(None, {'data-action': 'worktree-discuss-all', 'data-repo': '/Users/dev/workspace/api-service'})) == 1
            and '>Ask advisor about all 3</button>' in wt
            and '>Discuss all 4</button>' in wt
            and wt.index('worktree-advise-all') < wt.index('worktree-discuss-all') < wt.index('data-action="worktree-hide"')
        ),
    )
    check(
        'worktrees: Remove on a review row confirms what goes to the Trash and what stays in git, with no drawer',
        (
            (
                'Move /Users/dev/workspace/api-service/.worktrees/evidence to the Trash and unregister the worktree?' in dom_query(dom_wtreview).text
                or dom_query(dom_wtreview).has(None, {'title': lambda value: 'Move /Users/dev/workspace/api-service/.worktrees/evidence to the Trash and unregister the worktree?' in (value or '')})
            )
            and (
                'Goes with it: ignored files that only live here: .tmp/ (3 files, 1.2 MB)' in dom_query(dom_wtreview).text
                or dom_query(dom_wtreview).has(None, {'title': lambda value: 'Goes with it: ignored files that only live here: .tmp/ (3 files, 1.2 MB)' in (value or '')})
            )
            and (
                'Stays in git: branch feat/evidence, its commits and stashes.' in dom_query(dom_wtreview).text
                or dom_query(dom_wtreview).has(None, {'title': lambda value: 'Stays in git: branch feat/evidence, its commits and stashes.' in (value or '')})
            )
            and (
                'Its files stay in the Trash until you empty it; putting them back does not register the worktree again.' in dom_query(dom_wtreview).text
                or dom_query(dom_wtreview).has(None, {'title': lambda value: 'Its files stay in the Trash until you empty it; putting them back does not register the worktree again.' in (value or '')})
            )
            and 'id="confirm-layer" class="confirm-layer" hidden' not in dom_wtreview
            and (
                'Review worktree' not in dom_query(dom_wtreview).text
                and not dom_query(dom_wtreview).has(None, {'title': lambda value: 'Review worktree' in (value or '')})
            )
        ),
    )
    dw_agent = dom_wtdiscuss.split('id="agent-dock"', 1)[-1].split('id="drawer"', 1)[0]
    check(
        'worktrees: Discuss posts the worktree to the agent and shows the question as a card in the docked panel, staying on System',
        (
            'POST /agent/worktree' in pre(dom_wtdiscuss, 'mock-requests')
            and dom_query(dom_wtdiscuss).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
            and '<aside id="agent-dock" class="agent-dock" aria-labelledby="agent-dock-title">' in dom_wtdiscuss
            and 'id="agent-dock-body"><section class="agent-chat" id="agent-chat"' in dw_agent
            and dw_agent.count('agent-worktree-card') == 1
            and '<b>Can I delete this worktree?</b>' in dw_agent
            and 'branch feat/evidence' in dw_agent
            and 'Only ignored scratch files would be lost.' in dw_agent
        ),
    )
    cycle = json.loads(html.unescape(pre(dom_wtdockcycle, 'dock-cycle')) or '{}')
    in_dock = {'dock': True, 'drawer': False, 'chat': 'agent-dock-body', 'tab': 'system', 'focus': 'agent-input', 'end': True}
    check(
        'worktrees: the agent dock and the drawer replace each other, Escape while typing keeps the dock, Close returns the chat and focus',
        (
            cycle.get('open') == in_dock
            and {k: cycle.get('drawer', {}).get(k) for k in ('dock', 'drawer', 'chat', 'tab')} == {'dock': False, 'drawer': True, 'chat': 'agent-layout', 'tab': 'system'}
            and cycle.get('reopen') == in_dock
            and cycle.get('typing') == in_dock
            and {k: cycle.get('closed', {}).get(k) for k in ('dock', 'drawer', 'chat', 'tab', 'focus')} == {'dock': False, 'drawer': False, 'chat': 'agent-layout', 'tab': 'system', 'focus': 'worktree-discuss'}
            and 'class="agent-docked"' not in dom_wtdockcycle
        ),
    )
    check(
        "worktrees: Discuss with the agent off toasts the server's text and stays on System",
        (
            'class="toast danger">the system agent is off: set system_agent.enabled: true in the config file<' in dom_wtdiscussoff
            and dom_query(dom_wtdiscussoff).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
        ),
    )
    check(
        'worktrees: reviewed folder leaves the list after explicit Trash confirmation',
        (
            'POST /worktrees/review-trash' in pre(dom_wtreviewtrash, 'mock-requests')
            and '.worktrees/evidence' not in wt_block(dom_wtreviewtrash)
        ),
    )
    check(
        'worktrees: the disk card shows the volume and what worktrees occupy',
        (
            (
                '512.0 GB free of 2.0 TB' in dom_query(dom_wt).text
                or dom_query(dom_wt).has(None, {'title': lambda value: '512.0 GB free of 2.0 TB' in (value or '')})
            )
            and dom_query(dom_wt).has(None, {'data-w': '75'})
            and '<b>Worktrees</b> 1.5 GB' in dom_wt
            and '<span class="wt-size">1.5 GB</span>' in wt
        ),
    )

    def rc_block(dom_text):
        return dom_text.split('id="worktrees-reclaim"', 1)[-1].split('id="reclaim-tip"', 1)[0]

    def tile(dom_text, cls):
        return rc_block(dom_text).split(f'class="rc-tile {cls}"', 1)[-1].split('</div>', 1)[0]
    rc = rc_block(dom_wt)
    check('worktrees: tiles distinguish recorded cleanup history from current removable space', 'Freed · last 30 days' in tile(dom_wt, 'rc-freed') and '1.0 GB' in tile(dom_wt, 'rc-freed') and ('1 cleanup<' in tile(dom_wt, 'rc-freed')) and ('Freed · recorded' in tile(dom_wt, 'rc-alltime')) and ('3.0 GB' in tile(dom_wt, 'rc-alltime')) and ('2 cleanups' in tile(dom_wt, 'rc-alltime')) and ('1.5 GB' in tile(dom_wt, 'rc-removable')) and ('1 worktree<' in tile(dom_wt, 'rc-removable')) and ('worktrees-remove-removable' not in rc) and ('50 MB' in tile(dom_wt, 'rc-trash')) and ('Moved to the Trash' in tile(dom_wt, 'rc-trash')) and ('1 recorded cleanup' in tile(dom_wt, 'rc-trash')) and ('current Trash size is not measured' in tile(dom_wt, 'rc-trash')) and ('In the Trash' not in rc) and ('frees when the Trash is emptied' not in rc), rc[:600])
    check(
        'worktrees: the reclaimed chart has a column per day; only days with cleanups are buttons, labeled with their numbers',
        (
            len(dom_query(rc).find_all(None, {'class': 'rc-col'})) == 30
            and len(dom_query(rc).find_all(None, {'data-action': 'reclaim-day'})) == 1
            and dom_query(rc).has(None, {'aria-label': 'Space reclaimed per day, last 30 days'})
            and ': 1.0 GB freed by 1 cleanup, 50 MB moved to the Trash by 1 cleanup"' in rc
            and dom_query(rc).has(None, {'class': 'rc-seg rc-seg-trash', 'data-h': '5'})
            and '<span>2.0 GB</span><span>1.0 GB</span><span>0</span>' in rc
        ),
        f"cols={len(dom_query(rc).find_all(None, {'class': 'rc-col'}))} days={len(dom_query(rc).find_all(None, {'data-action': 'reclaim-day'}))}",
    )
    check(
        'worktrees: an old cached scan shows at once and the tab re-reads until the rescan lands',
        (
            'gone-since' not in wt_block(dom_wtrefresh)
            and (
                'refreshing…' not in dom_query(dom_wtrefresh).text
                and not dom_query(dom_wtrefresh).has(None, {'title': lambda value: 'refreshing…' in (value or '')})
            )
            and (
                'scanned in 4.2s' in dom_query(dom_wtrefresh).text
                or dom_query(dom_wtrefresh).has(None, {'title': lambda value: 'scanned in 4.2s' in (value or '')})
            )
        ),
    )
    check(
        'worktrees: while the daemon is still measuring, the tab re-reads until sizes land',
        (
            '<span class="wt-size">1.5 GB</span>' in wt_block(dom_wtsizing)
            and (
                'measuring…' not in dom_query(dom_wtsizing).text
                and not dom_query(dom_wtsizing).has(None, {'title': lambda value: 'measuring…' in (value or '')})
            )
            and '<b>Worktrees</b> 1.5 GB' in dom_wtsizing
        ),
    )

def run_clutter(page):
    check = page.check
    dom_clutter = page.fixture('dom_clutter')
    dom_clutteradvise = page.fixture('dom_clutteradvise')
    dom_clutter_view = page.fixture('dom_clutter_view')

    def cl_block(dom_text):
        return dom_text.split('id="clutter-container"', 1)[-1].split('id="tab-policy"', 1)[0]
    cl = cl_block(dom_clutter_view)
    check(
        'clutter: items grouped by project with kind, size, idle; Trash and Run only where the item offers them',
        (
            len(dom_query(cl).find_all(None, {'class': 'wt-row cl-row'})) == 3
            and 'data-action="clutter-trash" data-path="/Users/dev/workspace/api-service/.tmp">Move to Trash</button>' in cl
            and 'data-action="clutter-clean" data-name="go build" title="go clean -cache">Run go clean -cache</button>' in cl
            and len(dom_query(cl).find_all(None, {'data-action': 'clutter-trash'})) + len(dom_query(cl).find_all(None, {'data-action': 'clutter-clean'})) == 2
            and '&lt;i&gt;downloaded&lt;/i&gt; models' in cl
            and '<i>downloaded</i>' not in cl
            and '<span class="wt-repo-path" title="This machine">This machine</span>' in cl
        ),
    )
    check(
        'clutter: each project has Ask advisor; its plan renders escaped under the header with one step per line',
        (
            len(dom_query(cl).find_all(None, {'data-action': 'clutter-advise'})) == 2
            and 'data-action="clutter-advise" data-project="machine">Ask advisor</button>' in cl
            and '<div class="wt-advice cl-plan"><b>Advisor:</b> &lt;b&gt;Old&lt;/b&gt; scratch holds most of it.<ol><li>Move .tmp to the Trash</li><li>Ask the agent about feat/x</li></ol></div>' in cl
            and 'Caches are small' not in cl
        ),
    )
    cla = cl_block(dom_clutteradvise)
    check(
        'clutter: Ask advisor posts /cleanup/advise and the plan appears once the re-read has it',
        (
            'POST /cleanup/advise' in pre(dom_clutteradvise, 'mock-requests')
            and '<b>Advisor:</b> Caches are small; nothing urgent.<ol><li>Run go clean -cache</li></ol>' in cla
        ),
    )
    clr = cl_block(dom_clutter)
    check('clutter: Move to Trash posts after the dialog, drops the row and records the moved bytes', 'POST /cleanup/trash' in pre(dom_clutter, 'mock-requests') and '/api-service/.tmp' not in clr and ('1.0 MB moved to the Trash by recorded cleanups' in dom_clutter))

def run_worktrees_2(page):
    check = page.check
    dom_wtadopt = page.fixture('dom_wtadopt')
    dom_wtbatch = page.fixture('dom_wtbatch')
    dom_wtcadence = page.fixture('dom_wtcadence')
    dom_wtday = page.fixture('dom_wtday')
    dom_wtday_midnight = page.fixture('dom_wtday_midnight')
    dom_wtgroup = page.fixture('dom_wtgroup')
    dom_wthistory = page.fixture('dom_wthistory')
    dom_wtorphan = page.fixture('dom_wtorphan')
    dom_wtorphantrash = page.fixture('dom_wtorphantrash')
    dom_wtremovable = page.fixture('dom_wtremovable')
    dom_wtremove = page.fixture('dom_wtremove')
    dom_wtremovefail = page.fixture('dom_wtremovefail')
    dom_wtremoving = page.fixture('dom_wtremoving')
    dom_wtsearch = page.fixture('dom_wtsearch')

    def wt_block(dom_text):
        return dom_text.split('id="worktrees-container"', 1)[-1].split('data-action="clutter-rescan"', 1)[0]

    def rc_block(dom_text):
        return dom_text.split('id="worktrees-reclaim"', 1)[-1].split('id="reclaim-tip"', 1)[0]

    def tile(dom_text, cls):
        return rc_block(dom_text).split(f'class="rc-tile {cls}"', 1)[-1].split('</div>', 1)[0]
    wtr = wt_block(dom_wtremove)
    wtr_rows = len(dom_query(wtr).find_all(None, {'class': 'wt-row'}))
    wt_reqs = pre(dom_wtremove, 'mock-requests')
    check(
        'worktrees: Remove starts a background removal after the dialog; when it lands the row leaves and the tiles move',
        (
            'POST /worktrees/remove' in wt_reqs
            and '.worktrees/done' not in wtr
            and wtr_rows == 3
            and '4.5 GB' in tile(dom_wtremove, 'rc-alltime')
            and '3 cleanups' in tile(dom_wtremove, 'rc-alltime')
            and '2.5 GB' in tile(dom_wtremove, 'rc-freed')
            and '0 B' in tile(dom_wtremove, 'rc-removable')
            and 'wt-removal' not in wtr
        ),
        f'requests={wt_reqs!r} rows={wtr_rows}',
    )

    def toast_block(dom_text):
        return dom_text.split('id="removal-toast"', 1)[-1].split('</ul>', 1)[0] if dom_query(dom_text).has(None, {'id': 'removal-toast'}) else ''
    tr = dom_wtremove.split('id="removal-toast"', 1)[-1].split('id="drawer"', 1)[0] if dom_query(dom_wtremove).has(None, {'id': 'removal-toast'}) else ''
    check(
        'worktrees: when the removal lands its toast names what it reclaimed and links the history',
        (
            dom_query(dom_wtremove).has(None, {'class': 'toast toast-sticky removal-toast success'})
            and '<p class="rt-title" role="status">Removed feat/done</p>' in tr
            and '<p class="rt-sub">1.5 GB reclaimed</p>' in tr
            and 'data-action="worktrees-history">View cleanup history</button>' in tr
            and dom_query(tr).has(None, {'aria-valuenow': '100'})
        ),
        tr[:400],
    )
    wtb = wt_block(dom_wtbatch)
    batch_posts = pre(dom_wtbatch, 'mock-requests').count('POST /worktrees/remove')
    check(
        'worktrees: Remove all removes every removable row of the repository after one dialog',
        (
            batch_posts == 3
            and 'old-a' not in wtb
            and 'old-b' not in wtb
            and '.worktrees/done' not in wtb
            and 'worktree-remove-all' not in wtb
        ),
        f'posts={batch_posts}',
    )
    wto = wt_block(dom_wtorphan)
    check(
        "worktrees: a missing repository's folders are listed first with the reason and Open folder / Move to Trash",
        (
            wto.index('/Users/dev/gone-app') < wto.index('/Users/dev/workspace/api-service')
            and 'repository not found (moved or deleted) — the folders below still point to it' in wto
            and 'data-action="worktree-reveal" data-path="/Users/dev/.cursor/worktrees/gone-app/ctnj">Open folder</button>' in wto
            and dom_query(wto).has(None, {'data-action': 'worktree-trash-orphan'})
            and (
                '1 folder still points to it (listed first below)' in dom_query(dom_wtorphan).text
                or dom_query(dom_wtorphan).has(None, {'title': lambda value: '1 folder still points to it (listed first below)' in (value or '')})
            )
        ),
    )
    wtot = wt_block(dom_wtorphantrash)
    check(
        'worktrees: Move to Trash on an orphan posts /worktrees/trash after the dialog and the group and its error leave',
        (
            'POST /worktrees/trash' in pre(dom_wtorphantrash, 'mock-requests')
            and 'gone-app' not in wtot
            and (
                '1 folder still points to it' not in dom_query(dom_wtorphantrash).text
                and not dom_query(dom_wtorphantrash).has(None, {'title': lambda value: '1 folder still points to it' in (value or '')})
            )
        ),
    )
    wtg = wt_block(dom_wtremoving)
    tg = toast_block(dom_wtremoving)
    check(
        'worktrees: while a removal runs a toast follows it: phase, size and files, time in the phase, the bar',
        (
            dom_query(dom_wtremoving).has(None, {'class': 'toast toast-sticky removal-toast info'})
            and '<p class="rt-title" role="status">Removing feat/done</p>' in tg
            and '<span class="rt-step">deleting · 1.5 GB · 184,203 files</span>' in tg
            and dom_query(tg).has(None, {'role': 'progressbar'})
            and dom_query(tg).has(None, {'aria-valuenow': '50'})
            and 'rt-bar-running' in tg
            and dom_query(tg).has('span', {'class': 'rt-elapsed', 'data-since': None})
            and 's</span>' in tg
        ),
        tg[:600],
    )
    check(
        'worktrees: while a removal runs its row shows the phase marks, step and size, and Remove is disabled',
        (
            '<span class="wt-steps" aria-hidden="true"><i class="on"></i><i class="on"></i><i class="on"></i><i class="on"></i></span><b>Removing…</b> deleting · 1.5 GB · 184,203 files</p>' in wtg
            and '<button type="button" class="btn btn-danger btn-sm" disabled="">Removing…</button>' in wtg
            and not dom_query(wtg).has(None, {'data-action': 'worktree-remove'})
        ),
    )
    wtf = wt_block(dom_wtremovefail)
    check(
        'worktrees: a failed removal keeps the row with the error as text and offers Try again',
        (
            '.worktrees/done' in wtf
            and '<p class="wt-removal wt-removal-failed" role="alert"><b>Removal failed:</b> git worktree: &lt;b&gt;fatal&lt;/b&gt; could not remove' in wtf
            and '>Try again</button>' in wtf
        ),
    )
    tf = toast_block(dom_wtremovefail)
    check(
        "worktrees: a failed removal's toast stays with the error as text",
        (
            dom_query(dom_wtremovefail).has(None, {'class': 'toast toast-sticky removal-toast danger'})
            and '<p class="rt-title" role="status">Not removed: feat/done</p>' in tf
            and 'git worktree: &lt;b&gt;fatal&lt;/b&gt; could not remove' in tf
            and '<b>fatal</b>' not in tf
            and 'rt-bar-failed' in tf
        ),
        tf[:400],
    )
    tb = dom_wtbatch.split('id="removal-toast"', 1)[-1].split('id="drawer"', 1)[0] if dom_query(dom_wtbatch).has(None, {'id': 'removal-toast'}) else ''
    check(
        'worktrees: Remove all runs under one toast that ends with the count and bytes',
        (
            '<p class="rt-title" role="status">Removed 3 of 3 worktrees</p>' in tb
            and '4.5 GB reclaimed' in tb
        ),
        tb[:300],
    )
    rm_posts = pre(dom_wtremovable, 'mock-requests').count('POST /worktrees/remove')
    check(
        "worktrees: Removable now counts every repository's removable rows and Remove all there removes all of them",
        (
            '6.0 GB' in pre(dom_wtremovable, 'removable-tile')
            and '4 worktrees' in pre(dom_wtremovable, 'removable-tile')
            and 'Remove all 4' in pre(dom_wtremovable, 'removable-tile')
            and rm_posts == 4
            and 'web-app/.worktrees/landed' not in wt_block(dom_wtremovable)
        ),
        f"tile={pre(dom_wtremovable, 'removable-tile')!r} posts={rm_posts}",
    )
    hx_all = html.unescape(pre(dom_wthistory, 'history-all'))
    hx = dom_wthistory.split('id="drawer-body"', 1)[-1].split('id="drawer-foot"', 1)[0]
    check(
        'worktrees: History opens the ledger in the drawer by day, escaped; the Removed chip filters it',
        (
            'id="drawer-title-text">Cleanup history<' in dom_wthistory
            and '3 entries · 3.0 GB freed · 50 MB moved to the Trash' in hx_all
            and 'Moved an orphan folder to the Trash' in hx_all
            and '&lt;b&gt;branch&lt;/b&gt; feat/old kept' in hx_all
            and '<b>branch</b>' not in hx_all
            and '2 entries · 3.0 GB freed' in hx
            and 'Moved an orphan folder' not in hx
            and dom_query(hx).has(None, {'data-kind': 'removed', 'aria-pressed': 'true'})
        ),
        hx_all[:300],
    )
    for clock, day_dom in [('current time', dom_wtday), ('midnight', dom_wtday_midnight)]:
        hd = day_dom.split('id="drawer-body"', 1)[-1].split('id="drawer-foot"', 1)[0]
        check(
            f'worktrees: a chart column shows its numbers on hover and opens the history at that day ({clock})',
            (
                '1.0 GB freed by 1 cleanup50 MB moved to the Trash by 1 cleanup' in pre(day_dom, 'reclaim-tip-probe')
                and '2 entries · 1.0 GB freed · 50 MB moved to the Trash' in hd
                and dom_query(hd).has(None, {'data-action': 'history-day', 'data-day': None})
                and 'feat/old' not in hd
            ),
            f"tip={pre(day_dom, 'reclaim-tip-probe')!r} {hd[:200]}",
        )
    ws = wt_block(dom_wtsearch)
    check(
        'worktrees: the search box keeps rows whose branch, folder or repository matches, any case',
        (
            len(dom_query(ws).find_all(None, {'class': 'wt-row'})) == 1
            and '.worktrees/evidence' in ws
        ),
        f"rows={len(dom_query(ws).find_all(None, {'class': 'wt-row'}))}",
    )

    def gd(pid):
        try:
            return json.loads(html.unescape(pre(dom_wtgroup, pid)) or '{}')
        except ValueError:
            return {}
    gd_before, gd_evidence, gd_clutter, gd_cleared = (gd('gd-before'), gd('gd-evidence'), gd('gd-clutter'), gd('gd-cleared'))
    check(
        "worktrees: the header Search… box narrows the System tab's worktree rows in any case, the summary says how many are shown, clearing it restores them",
        (
            gd_before.get('rows') == 4
            and ' shown' not in gd_before.get('summary', '')
            and gd_evidence.get('rows') == 1
            and gd_evidence.get('summary', '').endswith('· 1 shown')
            and gd_cleared.get('rows') == 4
            and ' shown' not in gd_cleared.get('summary', '')
        ),
        f'before={gd_before} evidence={gd_evidence} cleared={gd_cleared}',
    )
    check(
        'worktrees: the header search narrows the clutter list too, and each empty list says why',
        (
            gd_before.get('clutter') == 3
            and gd_evidence.get('clutter') == 0
            and 'No clutter matches the search.' in gd_evidence.get('empty', [])
            and gd_clutter.get('clutter') == 1
            and gd_clutter.get('rows') == 0
            and gd_clutter.get('summary', '').endswith('· 0 shown')
            and 'No worktree matches this filter.' in gd_clutter.get('empty', [])
            and gd_cleared.get('clutter') == 3
        ),
        f'evidence={gd_evidence} clutter={gd_clutter}',
    )
    gd_reqs = html.unescape(pre(dom_wtgroup, 'mock-requests'))
    gd_agent = dom_wtgroup.split('id="agent-dock"', 1)[-1].split('id="drawer"', 1)[0]
    check(
        'worktrees: Ask advisor about all posts the repository and toasts how many worktrees it will work through',
        (
            'POST /worktrees/advise body={"repo":"/Users/dev/workspace/api-service"}' in gd_reqs
            and 'Asking the advisor about 3 worktrees, one at a time — notes appear under each row as it answers' in html.unescape(pre(dom_wtgroup, 'gd-toast'))
        ),
        gd_reqs,
    )
    check(
        'worktrees: Discuss all posts the repository and shows the group question in the docked panel, staying on System',
        (
            'POST /agent/worktree body={"repo":"/Users/dev/workspace/api-service"}' in gd_reqs
            and dom_query(dom_wtgroup).has(None, {'class': 'tab-btn active', 'data-tab': 'system'})
            and '<aside id="agent-dock" class="agent-dock" aria-labelledby="agent-dock-title">' in dom_wtgroup
            and gd_agent.count('agent-worktree-card') == 1
            and '<b>Which of these worktrees in this repository can I delete?</b>' in gd_agent
            and 'feat/evidence · review · merged: no' in gd_agent
        ),
        gd_reqs,
    )
    gap = pre(dom_wtcadence, 'remove-cadence')
    check(
        'worktrees: a removal started while a 5 s sizing re-read waits is re-read on its own 1.5 s cadence',
        (
            gap.isdigit()
            and int(gap) < 2000
        ),
        f'gap={gap!r}ms',
    )
    ta = toast_block(dom_wtadopt)
    check(
        'worktrees: a removal already running when the tab opens gets the progress toast without a click',
        (
            '<p class="rt-title" role="status">Removing feat/done</p>' in ta
            and 'checking it is still safe to remove' in ta
        ),
        ta[:300],
    )

def run_worktree_hierarchy(page):
    for width in (320, 390, 428, 768, 1280):
        dom = page.dom('?worktreehierarchy', served=True, window_size=(width, 800), fixture=payload_cases.worktree_reading_hierarchy())
        receipt = re.search(r'data-worktree-hierarchy="([^"]+)"', dom)
        state = json.loads(html.unescape(receipt.group(1))) if receipt else {}
        page.check(f'worktree hierarchy ({width}): receipt produced', bool(state), str(state))
        for name in ('completeIdentities', 'duplicateNames', 'bounds', 'actions', 'failure', 'touch', 'search'):
            page.check(f'worktree hierarchy ({width}): {name}', state.get(name) is True, str(state))


def run_filter_regressions(page):
    dom = page.dom('?raildemo', served=True, fixture={'script': 'cases_filter_regressions.js'})
    state = json.loads(html.unescape(pre(dom, 'filter-regression-probe')) or '{}')
    for key in ('state', 'focus', 'deselect', 'stale', 'intersection', 'all', 'searchEmpty', 'harnessVisible', 'harnessOff', 'harnessFocus', 'harnessOn', 'harnessAll', 'shared'):
        page.check(f'filter regressions: {key}', state.get(key) is True, str(state))


CASES = (
    Case('filter_regressions', run_filter_regressions),
    Case('worktree_hierarchy', run_worktree_hierarchy),
    Case('worktrees', run_worktrees, ('dom_memfam', 'dom_wt', 'dom_wtdiscuss', 'dom_wtdiscussoff', 'dom_wtdockcycle', 'dom_wtrefresh', 'dom_wtreview', 'dom_wtreviewtrash', 'dom_wtsizing')),
    Case('clutter', run_clutter, ('dom_clutter', 'dom_clutteradvise', 'dom_clutter_view')),
    Case('worktrees_2', run_worktrees_2, ('dom_wtadopt', 'dom_wtbatch', 'dom_wtcadence', 'dom_wtday', 'dom_wtday_midnight', 'dom_wtgroup', 'dom_wthistory', 'dom_wtorphan', 'dom_wtorphantrash', 'dom_wtremovable', 'dom_wtremove', 'dom_wtremovefail', 'dom_wtremoving', 'dom_wtsearch')),
)
