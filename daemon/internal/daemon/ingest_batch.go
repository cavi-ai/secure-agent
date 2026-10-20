package daemon

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// feedBatch uses only events already queued, adding no collection delay.
// A finding, sensitive read, or non-file event flushes preceding ordinary
// activity before its own persistence and publication.
func (i *eventIngest) feedBatch(events []event.Event) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return
	}
	var pending []event.Event
	opens := map[openKey]bool{}
	flush := func() {
		if len(pending) == 0 {
			return
		}
		result, err := i.deps.Store.PutFileEvents(pending)
		if result.HealthChanged && i.deps.PostureChanged != nil {
			i.deps.PostureChanged()
		}
		if err != nil {
			// One invalid row must not discard the other accepted events.
			for _, e := range pending {
				i.feedResolvedLocked(e, nil)
			}
		} else {
			for _, e := range pending {
				i.repeats.remember(e)
				noteFileFeed(i.deps.Store, e)
				if i.deps.Deltas != nil {
					de := e
					de.PriceClass = collect.EventPriceClass(e)
					i.deps.Deltas.Publish(api.Delta{Type: "event", Data: de})
				}
			}
		}
		pending = nil
		clear(opens)
	}
	for _, e := range events {
		file := e.Kind == event.KindFileOpen || e.Kind == event.KindFileWrite || e.Kind == event.KindFileDelete
		if !file || i.deps.Correlator.SensitiveFile(e) || e.CallID != "" {
			flush()
		}
		i.deps.Resolver.Resolve(&e)
		flags := i.deps.Correlator.Observe(e)
		if !file || len(flags) > 0 || i.deps.Correlator.SensitiveFile(e) || e.CallID != "" {
			flush()
			i.feedResolvedLocked(e, flags)
			continue
		}
		if isUnattributedFileEvent(e) {
			flush()
			noteFileFeed(i.deps.Store, e)
			continue
		}
		if e.Kind == event.KindFileOpen && opens[openKey{e.PID, e.Path}] {
			flush()
		}
		if i.repeats.seen(e) {
			flush()
			noteFileFeed(i.deps.Store, e)
			continue
		}
		pending = append(pending, e)
		if e.Kind == event.KindFileOpen {
			opens[openKey{e.PID, e.Path}] = true
		}
	}
	flush()
}
