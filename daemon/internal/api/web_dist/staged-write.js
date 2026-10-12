// The console's write protocol: stage the expected result, send the request,
// keep or revert, note, refetch. stage() and write() are the two halves;
// send() is the JSON POST most writes use.
function createStagedWrite({ telemetry, render, beginAttentionWrite, request }) {
  // A mutating action applies its expected result to the telemetry and
  // renders the affected panels BEFORE the request; the card changes under
  // the click. stage() snapshots the top-level keys the mutation replaces
  // (mutations assign new values, never edit in place) and returns revert(),
  // which restores a key only if nothing (SSE, reconcile) replaced it since.
  function stage(keys, panels, mutate) {
    const finishAttention = keys.includes('posture') ? beginAttentionWrite() : null;
    const before = keys.map(k => telemetry()[k]);
    mutate();
    const after = keys.map(k => telemetry()[k]);
    render(panels);
    const revert = () => {
      keys.forEach((k, i) => { if (telemetry()[k] === after[i]) telemetry()[k] = before[i]; });
      finishAttention?.(false);
      render(panels);
    };
    revert.commit = () => finishAttention?.(true);
    revert.isCurrent = () => !finishAttention || finishAttention.isCurrent();
    return revert;
  }

  const send = async (method, path, payload) => {
    const res = await request(path, {
      method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(await res.text());
    return res;
  };

  // Runs a staged write. A rejected or failed request reverts the staged
  // result and reports through failed/error; ok runs on success.
  async function write(revert, run, { ok, failed, error }) {
    try {
      const res = await run();
      if (res.ok) {
        await ok(res);
        return true;
      }
      revert();
      await failed(res);
    } catch (err) {
      revert();
      error(err);
    }
    return false;
  }

  return { stage, write, send };
}
