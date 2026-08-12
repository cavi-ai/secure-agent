package bus

import (
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Bus is a non-blocking in-process fan-out. A slow subscriber drops events
// rather than stalling collectors — collection must never block on delivery.
type Bus struct {
	mu   sync.RWMutex
	buf  int
	subs []chan event.Event
	done bool
}

func New(buffer int) *Bus { return &Bus{buf: buffer} }

func (b *Bus) Subscribe() <-chan event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan event.Event, b.buf)
	b.subs = append(b.subs, ch)
	return ch
}

func (b *Bus) Publish(e event.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.done {
		return
	}
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // subscriber full: drop, never block
		}
	}
}

func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return
	}
	b.done = true
	for _, ch := range b.subs {
		close(ch)
	}
}
