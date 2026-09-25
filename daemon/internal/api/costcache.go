package api

import (
	"strconv"
	"sync"
	"time"
)

const (
	// costCacheTTL is how long a computed cost report is served again for the
	// same parameters: the console and the menu bar re-ask /costs on every
	// refresh, and each report scans the window's model calls.
	costCacheTTL = 30 * time.Second
	// costCacheMax bounds the cached reports; the oldest is evicted first.
	costCacheMax = 32
)

// costCache holds recent cost reports by normalized request parameters.
// Concurrent requests for one key wait for the first one's result.
type costCache struct {
	mu      sync.Mutex
	now     func() time.Time // nil: time.Now
	entries map[string]*costEntry
}

type costEntry struct {
	at    time.Time
	ready chan struct{} // closed once val is set, or the compute panicked
	val   any
}

// costKey normalizes a report request: since and until to the minute, so a
// relative window ("24h") asked twice within a minute is one key.
func costKey(kind, by string, since, until time.Time, tz int) string {
	return kind + "|" + by + "|" + since.Truncate(time.Minute).UTC().Format(time.RFC3339) + "|" +
		until.Truncate(time.Minute).UTC().Format(time.RFC3339) + "|" + strconv.Itoa(tz)
}

// get returns the report cached under key when it is younger than
// costCacheTTL, else computes, caches and returns it. The value is shared
// between requests and must not be modified.
func (c *costCache) get(key string, compute func() any) any {
	c.mu.Lock()
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	if e, ok := c.entries[key]; ok && now.Sub(e.at) < costCacheTTL {
		c.mu.Unlock()
		<-e.ready
		if e.val != nil {
			return e.val
		}
		return compute()
	}
	if c.entries == nil {
		c.entries = make(map[string]*costEntry)
	}
	for k, e := range c.entries {
		if now.Sub(e.at) >= costCacheTTL {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= costCacheMax {
		oldest := ""
		for k, e := range c.entries {
			if oldest == "" || e.at.Before(c.entries[oldest].at) {
				oldest = k
			}
		}
		delete(c.entries, oldest)
	}
	e := &costEntry{at: now, ready: make(chan struct{})}
	c.entries[key] = e
	c.mu.Unlock()

	defer func() {
		if e.val == nil {
			c.mu.Lock()
			if c.entries[key] == e {
				delete(c.entries, key)
			}
			c.mu.Unlock()
		}
		close(e.ready)
	}()
	e.val = compute()
	return e.val
}
