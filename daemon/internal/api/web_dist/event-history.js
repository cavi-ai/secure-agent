// Page navigation owns only read state. Failed or superseded requests cannot
// move the current page, and cursors are never inferred from event timestamps.
function createEventHistoryPage(since = '') {
  return { cursor: '', trail: [], next: '', since, paged: false, pending: null, loading: false, error: '' };
}

function copyEventHistoryPage(state) {
  return { ...createEventHistoryPage(), ...state, trail: [...(state?.trail || [])], pending: null, loading: false, error: '' };
}

function validEventHistoryPage(value, session) {
  const record = v => !!v && typeof v === 'object' && !Array.isArray(v);
  if (!record(value) || typeof value.session_id !== 'string' || (session && value.session_id !== session)
      || !Array.isArray(value.rows) || value.rows.length > 200 || typeof value.has_earlier !== 'boolean'
      || (value.has_earlier ? typeof value.next_cursor !== 'string' || !value.next_cursor || value.next_cursor.length > 2048
        : value.next_cursor != null && value.next_cursor !== '')) return false;
  const ids = new Set();
  return value.rows.every(row => {
    if (!record(row) || typeof row.id !== 'string' || !/^[1-9][0-9]{0,18}$/.test(row.id)
        || ids.has(row.id) || !record(row.event) || row.event.session_id !== value.session_id) return false;
    ids.add(row.id);
    return true;
  }) && (!value.has_earlier || value.rows.length > 0);
}

function requestEventHistoryPage(state, direction) {
  if (state.loading || state.pending) return false;
  let cursor, trail;
  if (direction === 'earlier' && state.paged && state.next) {
    cursor = state.next; trail = [...state.trail, state.cursor];
  } else if (direction === 'newer' && state.trail.length) {
    trail = state.trail.slice(0, -1); cursor = state.trail.at(-1);
  } else if (direction === 'latest') {
    cursor = ''; trail = [];
  } else return false;
  state.pending = { cursor, trail };
  state.error = '';
  return true;
}

function acceptEventHistoryPage(state, value) {
  if (state.pending) {
    state.cursor = state.pending.cursor;
    state.trail = state.pending.trail;
  }
  state.pending = null; state.loading = false; state.error = '';
  state.paged = !Array.isArray(value);
  state.next = state.paged ? value.next_cursor || '' : '';
  return state.paged ? value.rows.map(row => ({ ...row.event, record_id: row.id })) : value;
}

function failEventHistoryPage(state) {
  state.error = state.pending ? 'The requested page could not be loaded. The current page is retained; retry the same control.' : '';
  state.pending = null; state.loading = false;
}
