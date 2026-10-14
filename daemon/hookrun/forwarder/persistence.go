package forwarder

import (
	"context"
	"time"
)

// The persistence worker is separate from recorder I/O, so an unavailable or
// slow recorder cannot prevent later captured records from reaching the outbox.
// SQLite serializes persistence and acknowledgments; neither holds the capture
// mutex while waiting for storage.
func (c *Client) persist(ctx context.Context) {
	tick := time.NewTicker(c.config.RetryInterval)
	defer tick.Stop()
	for ctx.Err() == nil {
		c.mu.Lock()
		var item queued
		found := false
		for _, q := range c.queue {
			if !q.persisted {
				item = q
				found = true
				break
			}
		}
		c.mu.Unlock()
		if found {
			err := c.outbox.put(ctx, item)
			if ctx.Err() != nil {
				return
			}
			c.mu.Lock()
			c.persistError = err != nil
			c.persistFull = isOutboxFull(err)
			if err == nil {
				for i := range c.queue {
					if c.queue[i].id == item.id && c.queue[i].session == item.session {
						c.queue[i].persisted = true
						break
					}
				}
			}
			c.mu.Unlock()
			c.notify()
			if err == nil {
				continue
			}
			// A flood of capture wakeups cannot bypass failed storage backoff.
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-c.persistWake:
		case <-tick.C:
		}
	}
}
