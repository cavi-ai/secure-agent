(() => {
  const {ready, idle, openTab, route} = window.DomTest;
  let writes = 0;
  route('/expected-egress', ({method}) => {
    if (method === 'POST') writes++;
    return {ok:true,status:200,json:async()=>({rules:[]})};
  });
  ready().then(async () => {
    const probe = {};
    try {
      openTab('egress'); await idle();
      const button = document.querySelector('[data-action="expect-egress"][data-episode-id="episode-routine"][data-kind="scope"]');
      probe.offered = !!button;
      // Identity changes after the choice rendered, before the user clicks.
      window.SA.t.egressEpisodes.find(e=>e.id==='episode-routine').observed.scope_complete = false;
      button.click(); await idle();
      probe.feedback = [...document.querySelectorAll('.toast')].some(el=>el.textContent.includes('incomplete'));
      probe.noWrite = writes === 0;
      probe.noConfirmation = !document.getElementById('confirm-layer')?.getClientRects().length;
    } catch (error) { probe.error = error.message; }
    document.body.dataset.egressExpectation = JSON.stringify(probe);
  });
})();
