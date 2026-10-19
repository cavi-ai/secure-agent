package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// esCollectorHealth publishes fixed health states independently of event IO.
// A slow status write cannot hold the event pump or its mutex. The runtime
// path is root-owned; its world-readable content carries no event evidence.
type esCollectorHealth struct {
	mu      sync.Mutex
	status  collect.ESCollectorStatus
	changed chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
}

func newESCollectorHealth(path string, pid int, interval time.Duration) *esCollectorHealth {
	ctx, cancel := context.WithCancel(context.Background())
	h := &esCollectorHealth{status: collect.ESCollectorStatus{PID: pid, State: "starting"}, changed: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{})}
	if exe, err := os.Executable(); err == nil {
		if info, err := os.Stat(exe); err == nil {
			at := info.ModTime().UTC()
			h.status.HelperMtime = &at
		}
	}
	go func() {
		defer close(h.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		publish := func() {
			h.mu.Lock()
			status := h.status
			status.UpdatedAt = time.Now().UTC()
			h.mu.Unlock()
			data, err := json.Marshal(status)
			if err == nil {
				err = safefile.WriteFileAtomic(path, data, 0644)
			}
			if err != nil {
				log.Printf("es-collector: health status write failed")
			}
		}
		publish()
		for {
			select {
			case <-ctx.Done():
				publish()
				return
			case <-h.changed:
				publish()
			case <-ticker.C:
				publish()
			}
		}
	}()
	return h
}

func (h *esCollectorHealth) setState(state string) {
	h.mu.Lock()
	changed := h.status.State != state
	h.status.State = state
	h.mu.Unlock()
	if changed {
		select {
		case h.changed <- struct{}{}:
		default:
		}
	}
}

func (h *esCollectorHealth) delivered() {
	now := time.Now().UTC()
	h.mu.Lock()
	h.status.LastDeliveryAt = &now
	h.mu.Unlock()
	h.setState("collecting")
}

func (h *esCollectorHealth) Close() {
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(time.Second): // status IO must not hold collector shutdown
	}
}
