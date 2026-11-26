// Masthead toggle: the center of the first sidebar control against the center
// of the page title's first line, with the sidebar open and collapsed and the
// second control hidden and shown.
(() => {
  const {ready, idle} = window.DomTest;
  ready().then(async () => {
    const probe = {viewport: innerWidth, states: []};
    const toggle = document.getElementById('btn-sidebar-toggle');
    const second = document.getElementById('btn-session-sidebar-toggle');
    const title = document.getElementById('page-title');
    const center = box => box.top + box.height / 2;
    const firstLine = () => {
      const range = document.createRange();
      range.selectNodeContents(title);
      return range.getClientRects()[0];
    };
    const open = () => toggle.getAttribute('aria-expanded') === 'true';
    try {
      for (const sidebarOpen of [true, false]) {
        if (open() !== sidebarOpen) { toggle.click(); await idle(); }
        for (const shown of [false, true]) {
          second.hidden = !shown;
          await idle();
          const offset = center(toggle.getBoundingClientRect()) - center(firstLine());
          probe.states.push({sidebarOpen: open(), shown, offset: Math.round(offset * 100) / 100});
        }
      }
    } catch (error) { probe.error = error.message; }
    probe.centered = probe.states.length === 4 && probe.states.every(state => Math.abs(state.offset) <= 1);
    document.body.dataset.mastheadToggle = JSON.stringify(probe);
  });
})();
