package api

import (
	"slices"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type sessionTimelineStore interface {
	QueryEventsResult(store.EventFilter) ([]event.Event, error)
}

// sessionTimeline answers one domain question, including its presentation
// ordering, independent of HTTP and the concrete SQLite store.
func sessionTimeline(st sessionTimelineStore, id string, limit int) ([]event.Event, error) {
	rows, err := st.QueryEventsResult(store.EventFilter{SessionID: id, Limit: limit})
	if err != nil {
		return nil, err
	}
	slices.Reverse(rows)
	return rows, nil
}

type sessionMemoryStore interface {
	QuerySessionMemory(string, *store.MemoryCursor, int) ([]store.MemoryFact, bool, error)
}

func sessionMemory(st sessionMemoryStore, id string, before *store.MemoryCursor, limit int) (memoryResponse, error) {
	facts, earlier, err := st.QuerySessionMemory(id, before, limit)
	if err != nil {
		return memoryResponse{}, err
	}
	response := memoryResponse{Rows: make([]memoryRow, 0, len(facts)), HasEarlier: earlier}
	for _, f := range facts {
		response.Rows = append(response.Rows, presentMemoryFact(f))
	}
	if earlier && len(facts) > 0 {
		response.NextCursor = encodeMemoryCursor(facts[0])
	}
	return response, nil
}
