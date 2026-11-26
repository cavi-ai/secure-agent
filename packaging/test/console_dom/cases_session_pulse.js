// Query the actual animation on a rendered active Session card.
(() => {
  const { ready, openTab, wait, stamp } = window.DomTest;
  const pulse = () => document.querySelector('#session-rail .session-card .sc-pulse.active');
  ready().then(async () => {
    openTab('sessions');
    if (await wait(() => pulse()?.getClientRects().length)) {
      stamp('session-pulse-motion', pulse().getAnimations().length ? 'animated' : 'still');
    }
  });
})();
