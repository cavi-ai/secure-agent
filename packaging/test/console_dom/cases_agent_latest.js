// Conversation reading and return-to-latest interactions.
(() => {
  const {route, ready, idle, openTab, realFetch} = window.DomTest;
  let messages = Array.from({length: 40}, (_, i) => ({id: i + 1, role: i % 2 ? 'assistant' : 'user',
    content: 'Recorded message ' + (i + 1) + '\n\n' + 'Retained conversation text for reading. '.repeat(12)}));
  let chatting = false, work = {}, reads = 0;
  const response = value => new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
  route('/agent/chat', () => {reads++; return response({messages, chatting, work});});
  route('/agent/worktree', () => response({message: messages[0]}));
  const checkpoint = () => realFetch('/__console_frame_checkpoint', {cache: 'no-store'});
  const thread = () => document.getElementById('agent-thread');
  const button = () => document.getElementById('agent-jump-latest');
  const input = () => document.getElementById('agent-input');
  const hidden = () => button().hidden && !button().getClientRects().length;
  const bottom = () => thread().scrollHeight - thread().scrollTop - thread().clientHeight < 2;
  const refresh = async () => {document.querySelector('[data-action="agent-refresh"]').click(); await idle(); await checkpoint();};
  const scroll = async top => {thread().scrollTop = top; thread().dispatchEvent(new Event('scroll')); await checkpoint();};
  const anchor = () => {
    const bounds = thread().getBoundingClientRect();
    const row = [...thread().children].find(node => node._saKey && node.getBoundingClientRect().bottom > bounds.top);
    return {key: row._saKey, offset: row.getBoundingClientRect().top - bounds.top};
  };
  const preserved = before => {
    const row = [...thread().children].find(node => node._saKey === before.key);
    return !!row && Math.abs(row.getBoundingClientRect().top - thread().getBoundingClientRect().top - before.offset) < 2;
  };
  const add = id => messages.push({id, role: 'assistant', content: 'New accepted reply ' + id});
  (async () => {
    const receipt = {};
    try {
      await ready(); openTab('agent'); await idle(); await checkpoint();
      receipt.initial = hidden() && bottom();
      input().value = 'Keep this draft';
      await scroll(500);
      receipt.earlier = !button().hidden && !!button().getClientRects().length && button().textContent === 'Jump to latest';
      const reading = anchor();
      add(41); await refresh();
      receipt.first = button().textContent === '1 new message · Jump to latest' && preserved(reading);
      messages[0].content += '\n\nUpdated old content. '.repeat(8);
      messages.push({id: 1000, origin: 'analysis', role: 'assistant', content: 'Separate analysis'});
      chatting = true; work = {state: 'preparing', elapsed_ms: 1000}; await refresh();
      const pending = thread().querySelector('.agent-pending');
      work = {state: 'inspecting', elapsed_ms: 5000, active_tool: 'inspect_snapshot', tool_calls: 2}; await refresh();
      receipt.updates = button().textContent === '1 new message · Jump to latest' && preserved(reading)
        && thread().querySelector('.agent-pending') === pending && thread().textContent.includes('Inspecting findings snapshot');
      chatting = false; add(42); await refresh();
      receipt.second = button().textContent === '2 new messages · Jump to latest' && preserved(reading);
      await scroll(thread().scrollHeight);
      receipt.manualBottom = hidden() && bottom();
      await scroll(500); add(43); await refresh();
      button().focus({preventScroll: true});
      const beforeReads = reads;
      button().click(); await checkpoint();
      receipt.jump = hidden() && bottom() && document.activeElement === input() && input().value === 'Keep this draft' && reads === beforeReads;
      add(44); await refresh();
      receipt.follow = hidden() && bottom() && input().value === 'Keep this draft';

      await scroll(500); add(45); await refresh();
      const dockReading = anchor();
      openTab('home'); await checkpoint();
      await window.discussWorktree('/fixture/worktree'); await idle(); await checkpoint();
      receipt.dockOpen = !!document.getElementById('agent-dock').getClientRects().length && preserved(dockReading)
        && button().textContent === '1 new message · Jump to latest' && input().value === 'Keep this draft';
      document.querySelector('[data-action="agent-dock-close"]').click(); await checkpoint();
      thread().dispatchEvent(new Event('scroll'));
      openTab('agent'); await idle(); await checkpoint();
      receipt.dockClose = preserved(dockReading) && button().textContent === '1 new message · Jump to latest';
      openTab('home'); await checkpoint();
      await window.discussWorktree('/fixture/worktree'); await idle(); await checkpoint();
      document.querySelector('[data-action="agent-dock-expand"]').click(); await idle(); await checkpoint();
      receipt.dockExpand = preserved(dockReading) && button().textContent === '1 new message · Jump to latest';
      await scroll(thread().scrollHeight);
      openTab('home'); await checkpoint();
      await window.discussWorktree('/fixture/worktree'); await idle(); await checkpoint();
      receipt.dockFollow = hidden() && bottom();
      document.querySelector('[data-action="agent-dock-expand"]').click(); await idle(); await checkpoint();
      receipt.returnFollow = hidden() && bottom();

      messages = []; await refresh();
      receipt.empty = hidden() && thread().textContent.includes('What would you like to take care of?');
      route('/agent/status', () => response({enabled: false})); await refresh();
      receipt.disabled = hidden() && thread().textContent.includes('Secure Agent chat is off');
      receipt.bounds = document.documentElement.scrollWidth <= document.documentElement.clientWidth;
    } catch (error) {receipt.error = String(error.stack || error);}
    document.body.dataset.agentLatest = JSON.stringify(receipt);
  })();
})();
