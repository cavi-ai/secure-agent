(() => {
  setTimeout(async () => {
    const state = {viewport:innerWidth};
    const { openTab, realFetch } = window.DomTest;
    const frame = () => realFetch('/__console_frame_checkpoint', {cache: 'no-store'});
    const visible = el => {
      if (!el?.getClientRects().length) return false;
      const r = el.getBoundingClientRect();
      return r.top >= 0 && r.left >= 0 && r.bottom <= innerHeight && r.right <= innerWidth;
    };
    try {
      openTab('home'); await frame();
      const nav = document.getElementById('console-sidebar');
      const toggle = document.getElementById('btn-sidebar-toggle');
      const headerSpacing = () => {
        window.scrollTo({top:0,behavior:'instant'});
        const button = toggle.getBoundingClientRect();
        const header = document.querySelector('.masthead').getBoundingClientRect();
        const title = document.getElementById('page-title').getBoundingClientRect();
        const app = document.querySelector('.app');
        const inset = parseFloat(getComputedStyle(app).paddingLeft);
        const slot = document.querySelector('.sidebar-control-slot').getBoundingClientRect();
        const controls = document.querySelector('.sidebar-controls').getBoundingClientRect();
        return Math.abs(button.left - app.getBoundingClientRect().left - inset) < 1
          && Math.abs(button.top - header.top) < 1 && title.left >= button.right + 11
          && slot.height >= controls.height && button.width >= (innerWidth < 1100 ? 44 : 36);
      };
      state.sessionHiddenOnHome = !document.getElementById('btn-session-sidebar-toggle').getClientRects().length;
      state.navigation = visible(toggle) && toggle.getAttribute('aria-expanded') === 'true';
      state.expandedHeader = headerSpacing();
      window.scrollTo(0, document.body.scrollHeight); await frame();
      state.navigationScroll = visible(toggle);
      toggle.click(); await frame();
      state.navigationClose = nav.hidden && visible(toggle) && toggle.getAttribute('aria-expanded') === 'false';
      state.collapsedHeader = headerSpacing() && document.querySelector('.app').getBoundingClientRect().left === 0;
      toggle.click(); await frame();
      state.navigationOpen = !nav.hidden && visible(toggle) && toggle.getAttribute('aria-expanded') === 'true';
      state.restoredHeader = headerSpacing();
      const marks = [...document.querySelectorAll('.session-daily-card .harness-tile')];
      state.icons = marks.length > 0 && marks.every(el => el.getBoundingClientRect().width <= 16);
      const rows = [...document.querySelectorAll('.session-daily-card')];
      state.rows = innerWidth < 720 || rows.length > 0 && rows.every(el => el.getBoundingClientRect().height <= 74);
      openTab('sessions'); await window.selectSession('sess-codex-3'); await frame();
      const session = document.getElementById('btn-session-sidebar-toggle');
      state.sessionControl = visible(session) && !session.hidden;
      state.sessionHeader = headerSpacing();
      if (session.getAttribute('aria-expanded') === 'false') { session.click(); await frame(); }
      const selected = window.SA.selectedSessionId;
      window.scrollTo(0, document.body.scrollHeight); await frame();
      state.sessionScroll = visible(session);
      session.click(); await frame();
      state.sessionClose = visible(session) && session.getAttribute('aria-expanded') === 'false'
        && !document.getElementById('session-rail').getClientRects().length;
      session.click(); await frame();
      state.sessionOpen = visible(session) && session.getAttribute('aria-expanded') === 'true'
        && !!document.getElementById('session-rail').getClientRects().length;
      state.selectionRetained = window.SA.selectedSessionId === selected;
      state.fits = document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    } catch (error) { state.error = error.message; }
    document.body.dataset.consoleDensity = JSON.stringify(state);
  }, 2500);
})();
