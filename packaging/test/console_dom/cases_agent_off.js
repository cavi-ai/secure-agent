// Observe what the disabled screen's Copy action sends to the clipboard.
(() => {
  const { ready, openTab, wait, stamp } = window.DomTest;
  const button = () => document.querySelector('.agent-off button[data-action="agent-copy"]');
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: async text => stamp('agent-config-copied', text) }
  });
  ready().then(async () => {
    openTab('agent');
    if (await wait(button)) button().click();
  });
})();
