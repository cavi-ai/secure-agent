// Own the agent controller workflow through explicit state and callbacks.
function createAgentController({ state, actions }) {
  function agentBusy() {
    return !!(state.agentState.sending || state.agentState.actionRequests.size || (state.agentState.chat && state.agentState.chat.chatting) || (state.agentState.runs || []).some(r => r.status === 'running'));
  }
  async function loadAgent(parts) {
    const want = parts || ['status', 'chat', 'plans', 'runs', 'recommendations'];
    const wasBusy = agentBusy();
    const versions = want.map(p => state.agentState.readVersion[p] = (state.agentState.readVersion[p] || 0) + 1);
    try {
      const got = await Promise.all(want.map(p => actions.agentFetch(state.AGENT_PATHS[p])));
      want.forEach((p, i) => { if (state.agentState.readVersion[p] === versions[i]) state.agentState[p] = got[i]; });
      state.agentState.error = '';
      if (want.includes('status')) actions.fillAgentHarnesses();
    } catch (err) {
      state.agentState.error = "Couldn't load the system agent: " + (err.message || err);
    }
    actions.markDirty('agent');
    actions.followAgent(wasBusy);
  }

  async function sendAgentMessage() {
    if (agentBusy()) return;
    if (!state.agentState.status?.enabled || state.agentState.status.reason) {
      state.agentState.sendError = state.agentState.status?.reason || (state.agentState.status
        ? 'Enable chat in Settings → Secure Agent before sending.' : 'Still connecting to Secure Agent. Please wait.');
      actions.renderNow(['agent']);
      return;
    }
    const draft = state.agentInput ? state.agentInput.value : '';
    const text = draft.trim();
    if (!text) return;
    // Paint before the network request. The server alone masks and accepts
    // message text; never create an optimistic copy of an unmasked draft.
    state.agentState.sending = true;
    state.agentState.sendError = '';
    actions.renderNow(['agent']);
    try {
      const res = await actions.agentFetch('/agent/chat', { method: 'POST',
        body: { message: text, workdir: state.agentWorkdirInput.value.trim() } });
      if (!res?.message?.id) throw new Error('The daemon did not acknowledge the message');
      if (state.agentInput.value === draft) state.agentInput.value = '';
      const chat = state.agentState.chat || (state.agentState.chat = { messages: [] });
      // An older GET cannot erase a message accepted after that GET started.
      state.agentState.readVersion.chat = (state.agentState.readVersion.chat || 0) + 1;
      if (!(chat.messages || []).some(m => m.id === res.message.id)) chat.messages = [...(chat.messages || []), res.message];
      chat.chatting = true;
    } catch (err) {
      state.agentState.sendError = 'Delivery could not be confirmed: ' + (err.message || err) + '. Your draft is kept; check the conversation before retrying.';
      await actions.loadAgent(['chat']);
    } finally {
      state.agentState.sending = false;
      actions.renderNow(['agent']);
      actions.followAgent(false);
    }
  };

  async function runLocalAgentAction(messageId) {
    const m = [...((state.agentState.chat && state.agentState.chat.messages) || []), ...(state.agentState.recommendations || [])].find(x => x.id === messageId);
    if (!m || !m.local_command || m.local_run_id || state.agentState.actionRequests.has(messageId)) return;
    const action = m.local_command;
    const mode = action.mode === 'terminal' ? 'in Terminal' : 'headless';
    state.agentState.actionRequests.add(messageId);
    actions.renderNow(['agent']);
    try {
      const ok = await actions.window.saConfirm(`Run this exact local command ${mode} in ${action.workdir}?\n\n${action.command}\n\nIt runs with your account's file and network access. No harness receives this chat or command.`,
        { title: 'Confirm local command', okLabel: 'Run command', danger: true });
      if (!ok) return;
      const res = await actions.agentFetch('/agent/actions', { method: 'POST', body: { message_id: messageId } });
      m.local_run_id = res.run.id;
      state.agentState.readVersion.chat = (state.agentState.readVersion.chat || 0) + 1;
      state.agentState.readVersion.runs = (state.agentState.readVersion.runs || 0) + 1;
      state.agentState.runs = [res.run, ...(state.agentState.runs || []).filter(r => r.id !== res.run.id)];
      // Keep the conversation and focus in place; execution is visible on
      // the command proposal as well as in History.
      actions.loadAgent(['chat', 'runs', 'recommendations']);
    } catch (err) {
      actions.showToast('Local command not run: ' + (err.message || err), 'danger');
    } finally {
      state.agentState.actionRequests.delete(messageId);
      actions.renderNow(['agent']);
      actions.followAgent(false);
    }
  };

  return { agentBusy, loadAgent, sendAgentMessage, runLocalAgentAction };
}
