package api

import (
	"errors"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

var (
	errEndpointEvents   = errors.New("endpoint events unavailable")
	errEndpointSessions = errors.New("endpoint sessions unavailable")
)

// endpointEvidenceStore supplies recorded connections and their sessions.
type endpointEvidenceStore interface {
	QueryEvents(store.EventFilter) ([]event.Event, error)
	GetSessionBounded(string) (model.Session, bool, error)
}

// endpointConnections reads the last week's connections to host (at most 50)
// and each distinct durable session behind them, in first-seen order. Any
// failed read rejects the whole answer; empty lists encode as [].
func endpointConnections(st endpointEvidenceStore, host string, now time.Time) ([]event.Event, []model.Session, error) {
	evs, err := st.QueryEvents(store.EventFilter{
		RemoteHost: host,
		Since:      now.Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Limit:      50,
	})
	if err != nil {
		return nil, nil, errEndpointEvents
	}
	if evs == nil {
		evs = []event.Event{}
	}
	sessions := []model.Session{}
	seen := map[string]bool{}
	for _, e := range evs {
		if e.SessionID == "" || seen[e.SessionID] {
			continue
		}
		seen[e.SessionID] = true
		s, ok, err := st.GetSessionBounded(e.SessionID)
		if err != nil {
			return nil, nil, errEndpointSessions
		}
		if ok {
			sessions = append(sessions, s)
		}
	}
	return evs, sessions, nil
}

// attachHostAdvice joins the advisor's host verdict onto each endpoint row in
// one batch. Advice is optional: a failed read leaves rows unadvised and keeps
// valid verdicts.
func attachHostAdvice(reader advisorVerdictsReader, rows []UninspectedEndpoint) {
	ids := make([]string, len(rows))
	for i, ep := range rows {
		ids[i] = "host:" + ep.Agent + "|" + ep.Host
	}
	verdicts, _ := reader.AdvisorVerdictsFor(ids, "host")
	for i, id := range ids {
		if v, ok := verdicts[id]; ok {
			rows[i].Assessment = v.Assessment
			rows[i].Rationale = v.Rationale
		}
	}
}
