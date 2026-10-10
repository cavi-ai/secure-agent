package store

import "github.com/cavi-ai/secure-agent/daemon/internal/event"

// RecordedEvent retains the database identity alongside the existing event.
// IDs order retained records, not occurrence time or causal order.
type RecordedEvent struct {
	ID    int64
	Event event.Event
}

func (s *Store) QueryRecordedEvents(f EventFilter, beforeID int64) (out []RecordedEvent, earlier bool, readErr error) {
	defer func() { s.noteRead("events", readErr) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	f.Limit = limit + 1
	q, args := eventRecordQuery(f, true, beforeID)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out = []RecordedEvent{}
	for rows.Next() {
		var id int64
		e, err := scanEvent(rows, &id)
		if err != nil {
			return nil, false, err
		}
		out = append(out, RecordedEvent{ID: id, Event: e})
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		out, earlier = out[:limit], true
	}
	return out, earlier, nil
}
