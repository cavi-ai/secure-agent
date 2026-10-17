// Session geometry and resize observation are independent of evidence reads.
function createSessionLayout({ getView }) {
  let sessionHeightFrame = 0;
  let sessionHeightChrome = null;
  const sessionHeightObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(scheduleSessionWorkbenchHeight) : null;
  function scheduleSessionWorkbenchHeight() {
    if (sessionHeightFrame) return;
    sessionHeightFrame = requestAnimationFrame(() => {
      sessionHeightFrame = 0;
      const panel = document.getElementById('session-board-panel');
      if (!panel || !panel.classList.contains('session-workbench') || !panel.getClientRects().length) return;
      const body = panel.querySelector('.session-detail-body');
      const followLatest = body && body.scrollHeight - body.clientHeight - body.scrollTop < 64;
      const chrome = panel.querySelector('.session-detail-chrome');
      if (sessionHeightObserver && chrome !== sessionHeightChrome) {
        if (sessionHeightChrome) sessionHeightObserver.unobserve(sessionHeightChrome);
        if (chrome) sessionHeightObserver.observe(chrome);
        sessionHeightChrome = chrome;
      }
      const style = getComputedStyle(panel);
      const bodyStyle = body && getComputedStyle(body);
      const paragraph = body?.querySelector('.sm-content p, .sd-outcome p, .sm-state');
      const lineHeight = paragraph ? parseFloat(getComputedStyle(paragraph).lineHeight) || 18 : 18;
      const viewportHeight = window.visualViewport?.height || window.innerHeight;
      const readingReserve = Math.max(Math.ceil(viewportHeight / 2), Math.ceil(8 * lineHeight + 44
        + (parseFloat(bodyStyle?.paddingTop) || 0) + (parseFloat(bodyStyle?.paddingBottom) || 0)));
      const visibleHeight = el => el?.getClientRects().length ? el.getBoundingClientRect().height : 0;
      const detailVisible = !!body?.getClientRects().length;
      const splitMinimum = (detailVisible ? visibleHeight(chrome) : 0) + readingReserve;
      const minimum = visibleHeight(panel.querySelector('.session-toolbar')) + splitMinimum
        + (parseFloat(style.borderTopWidth) || 0) + (parseFloat(style.borderBottomWidth) || 0);
      const bottom = parseFloat(getComputedStyle(document.querySelector('.app') || document.body).paddingBottom) || 16;
      const height = Math.floor(viewportHeight - panel.getBoundingClientRect().top - bottom);
      // When chrome and a useful reading area cannot fit, the document scrolls.
      panel.classList.toggle('session-workbench-short', height < minimum);
      for (const [name, value] of [['--session-workbench-height', Math.max(minimum, height) + 'px'], ['--session-split-height', splitMinimum + 'px']]) {
        if (panel.style.getPropertyValue(name) !== value) panel.style.setProperty(name, value);
      }
      // Sizing changes the scroll range after the initial detail render.
      if (followLatest) body.scrollTop = body.scrollHeight;
      const latest = panel.querySelector('[data-action="session-latest"]');
      if (latest && body) latest.hidden = getView() === 'hooks' || body.scrollHeight - body.clientHeight - body.scrollTop < 64;
    });
  }
  window.addEventListener('resize', scheduleSessionWorkbenchHeight);
  window.visualViewport?.addEventListener('resize', scheduleSessionWorkbenchHeight);
  if (sessionHeightObserver) {
    for (const el of document.querySelectorAll('.masthead, #tabs-bar, .subtabs, #session-board-panel .session-toolbar')) sessionHeightObserver.observe(el);
  }
  return { schedule: scheduleSessionWorkbenchHeight };
}
