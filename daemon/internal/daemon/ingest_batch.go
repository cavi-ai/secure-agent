package daemon

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// heldFile is an ordinary file event that waits for the pending batch: a
// skipped event's feed clock must not pass rows not stored yet, and a repeat
// of a pending open folds only once that open is stored.
type heldFile struct {
	e      event.Event
	repeat bool
}

// feedBatch uses only events already queued, adding no collection delay.
// A finding, sensitive read, or non-file event flushes preceding ordinary
// activity before its own persistence and publication. Skipped and repeated
// file events wait for the batch instead of splitting it: they outnumber
// agent file activity, and a commit per agent event multiplies the bytes
// written per stored row.
func (i *eventIngest) feedBatch(events []event.Event) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return
	}
	var pending []event.Event
	var held []heldFile
	opens := map[openKey]bool{}
	flush := func() {
		if len(pending) > 0 {
			result, err := i.deps.PutFileEvents(pending)
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
		for _, h := range held {
			if h.repeat {
				// Folds into its stored open; stored itself when that
				// open's write failed.
				i.feedResolvedLocked(h.e, nil)
			} else {
				noteFileFeed(i.deps.Store, h.e)
			}
		}
		held = held[:0]
	}
	skip := func(e event.Event) {
		if len(pending) == 0 {
			noteFileFeed(i.deps.Store, e)
			return
		}
		held = append(held, heldFile{e: e})
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
			skip(e)
			continue
		}
		if e.Kind == event.KindFileOpen && opens[openKey{e.PID, e.Path}] {
			held = append(held, heldFile{e: e, repeat: true})
			continue
		}
		if i.repeats.seen(e) {
			skip(e)
			continue
		}
		pending = append(pending, e)
		if e.Kind == event.KindFileOpen {
			opens[openKey{e.PID, e.Path}] = true
		}
		if len(pending) == store.MaxFileBatch {
			flush()
		}
	}
	flush()
}
