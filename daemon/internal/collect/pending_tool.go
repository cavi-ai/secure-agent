package collect

import (
	"container/list"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"time"
)

const pendingToolLifetime = 24 * time.Hour

// Retire unfinished calls visibly while preserving main's bounded queue and
// late-result fallback. Pairing duration is never invented after retirement.
func (p *pendingTools) add(id, session string, tool pendingTool) []event.Event {
	if p.byID == nil {
		p.byID = make(map[string]*list.Element)
	}
	if previous := p.byID[id]; previous != nil {
		p.order.Remove(previous)
	}
	p.byID[id] = p.order.PushBack(pendingToolEntry{id: id, session: session, tool: tool})
	return p.expire(tool.ts)
}

func (p *pendingTools) expire(now time.Time) []event.Event {
	var events []event.Event
	for e := p.order.Front(); e != nil; e = p.order.Front() {
		call := e.Value.(pendingToolEntry)
		if len(p.byID) <= pendingToolLimit && now.Sub(call.tool.ts) <= pendingToolLifetime {
			break
		}
		delete(p.byID, call.id)
		p.order.Remove(e)
		p.evicted = true
		if call.session != "" {
			events = append(events, event.Event{Kind: event.KindToolCall, TS: call.tool.ts, SessionID: call.session, CallID: call.id, ToolName: call.tool.name, ToolStatus: "incomplete"})
		}
	}
	return events
}
