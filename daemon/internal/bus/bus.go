package bus

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Bus is a non-blocking in-process fan-out. A slow subscriber drops events
// rather than stalling collectors — collection must never block on delivery.
type Bus struct {
	mu      sync.RWMutex
	buf     int
	subs    []chan event.Event
	done    bool
	dropped atomic.Uint64
	// droppedAt is the Unix-nanosecond time of the last drop, zero before any.
	droppedAt atomic.Int64
}

func New(buffer int) *Bus { return &Bus{buf: buffer} }

func (b *Bus) Subscribe() <-chan event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan event.Event, b.buf)
	if b.done {
		// Already closed: hand back a closed channel so the subscriber drains
		// and exits instead of leaking a channel nothing will ever write to.
		close(ch)
		return ch
	}
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
			b.dropped.Add(1)
			b.droppedAt.Store(time.Now().UnixNano())
		}
	}
}

// TryPublish offers an event to every subscriber without waiting for capacity.
// On rejection nothing is delivered: a durable source can retry without
// duplicating deliveries or counting retained evidence as lost. It leaves a
// quarter of each subscriber's buffer free, so a durable backlog never takes
// the slots Publish needs and cannot retry. The exclusive lock excludes other
// publishers between the capacity check and fan-out.
func (b *Bus) TryPublish(e event.Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return false
	}
	for _, ch := range b.subs {
		if len(ch) >= cap(ch)-cap(ch)/4 {
			return false
		}
	}
	for _, ch := range b.subs {
		ch <- e // consumers can only free capacity while publishers are excluded
	}
	return true
}

// Dropped is the number of per-subscriber publishes that found a full buffer.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Dropping reports current delivery pressure, not the lifetime loss count.
// Once consumers free capacity, earlier losses remain in Dropped and DroppedAt.
func (b *Bus) Dropping() bool {
	if b.Dropped() == 0 {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		if len(ch) == cap(ch) {
			return true
		}
	}
	return false
}

// DroppedAt is when the last drop happened; zero before any.
func (b *Bus) DroppedAt() time.Time {
	if ns := b.droppedAt.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
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
