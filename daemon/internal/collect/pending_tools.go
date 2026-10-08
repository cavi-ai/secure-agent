package collect

import (
	"container/list"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Budget per transcript. Unfinished calls cannot grow parser memory forever.
const pendingToolLimit = 1024

type pendingTools struct {
	order   list.List
	byID    map[string]*list.Element
	evicted bool
}

type pendingToolEntry struct {
	id      string
	session string
	tool    pendingTool
}

func (p *pendingTools) put(id string, tool pendingTool) {
	p.add(id, "", tool)
}

func (p *pendingTools) completion(id, session, status string, at time.Time) (event.Event, bool) {
	if id == "" || session == "" {
		return event.Event{}, false
	}
	e := event.Event{Kind: event.KindToolCall, TS: at, SessionID: session, CallID: id, ToolStatus: status}
	if el := p.byID[id]; el != nil {
		start := el.Value.(pendingToolEntry).tool
		p.order.Remove(el)
		delete(p.byID, id)
		e.TS, e.ToolName = start.ts, start.name
		e.DurationMs = max(0, at.Sub(start.ts).Milliseconds())
		return e, true
	}
	if !p.evicted {
		return event.Event{}, false
	}
	// The start event was already emitted. Preserve the late completion's
	// status; its timing is unavailable rather than guessed from this record.
	e.Detail = "tool duration unavailable: start not retained"
	return e, true
}
