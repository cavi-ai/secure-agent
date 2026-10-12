package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type snapshotRowsStore interface {
	ListSessions(store.SessionFilter) ([]model.Session, error)
	QueryEvents(store.EventFilter) ([]event.Event, error)
}

// readSnapshotRows loads the bounded session and event rows used by the
// snapshot. Neither source can produce a successful partial snapshot.
func readSnapshotRows(st snapshotRowsStore) ([]model.Session, []event.Event, error) {
	sessions, err := st.ListSessions(store.SessionFilter{Limit: 100})
	if err != nil {
		return nil, nil, err
	}
	events, err := st.QueryEvents(store.EventFilter{Limit: 50})
	if err != nil {
		return nil, nil, err
	}
	return sessions, events, nil
}
