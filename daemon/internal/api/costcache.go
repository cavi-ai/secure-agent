package api

import (
	"encoding/json"
	"log"
	"strconv"
	"sync"
	"time"
)

const (
	// costCacheTTL is how long a computed report answers without a new
	// computation: the console and the menu bar re-ask /costs on every
	// refresh, and each report scans the window's model calls.
	costCacheTTL = 30 * time.Second
	// costCacheMax bounds the cached reports; the least recently asked is
	// evicted first.
	costCacheMax = 32
	// costsCacheName is the scan_cache row the /costs reports are saved in.
	costsCacheName = "costs.reports"
)

// scanCacheStore is where a costCache saves its reports. *store.Store
// satisfies it.
type scanCacheStore interface {
	ScanCache(name string) ([]byte, time.Time, bool)
	PutScanCache(name string, body []byte, at time.Time)
}

// costCache holds reports by request parameters. A plain request waits for a
// report younger than costCacheTTL: the cached one, else a computation that
// concurrent requests for the key share. A stale request answers at once from
// any cached report, however old, and has one older than the TTL computed
// again in the background. With st set, the reports are saved under saveAs
// after each computation and restored on first use, so a restarted daemon
// answers from them.
type costCache[T any] struct {
	now    func() time.Time // nil: time.Now
	st     scanCacheStore   // nil: memory only
	saveAs string

	loadOnce sync.Once
	mu       sync.Mutex
	entries  map[string]*costEntry[T]
	dirty    bool           // a computation landed since the last save began
	saving   bool           // the saver goroutine is running
	bg       sync.WaitGroup // background computations and saves; tests wait on it
}

type costEntry[T any] struct {
	val    T
	at     time.Time     // when val's computation began; zero: no value yet
	used   time.Time     // last asked, for eviction
	flight chan struct{} // non-nil while a computation runs; closed when it ends
}

// savedCostReport is one report as saved in the store.
type savedCostReport[T any] struct {
	At     time.Time `json:"at"`
	Report T         `json:"report"`
}

// costKey names a report request by its parameters as asked: a lookback
// ("24h") is one key however late it is asked, so a stale request finds the
// report last computed for it.
func costKey(kind, by, since, until string, tz int) string {
	return kind + "|" + by + "|" + since + "|" + until + "|" + strconv.Itoa(tz)
}

func (c *costCache[T]) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// get returns key's report, when its computation began, and whether a newer
// one is being computed in the background (stale requests only). The value
// is shared between requests and must not be modified.
func (c *costCache[T]) get(key string, stale bool, compute func() T) (val T, at time.Time, refreshing bool) {
	c.load()
	for {
		c.mu.Lock()
		e := c.entryLocked(key)
		now := c.clock()
		e.used = now
		has := !e.at.IsZero()
		if has && now.Sub(e.at) < costCacheTTL {
			val, at = e.val, e.at
			c.mu.Unlock()
			return val, at, false
		}
		if has && stale {
			if e.flight == nil {
				f := c.startLocked(e)
				c.bg.Add(1)
				go func() {
					defer c.bg.Done()
					defer func() {
						if r := recover(); r != nil {
							log.Printf("api: background cost report %q: %v", key, r)
						}
					}()
					c.run(e, f, compute)
				}()
			}
			val, at = e.val, e.at
			c.mu.Unlock()
			return val, at, true
		}
		if f := e.flight; f != nil {
			c.mu.Unlock()
			<-f
			continue // its value, or this request computes when it panicked
		}
		f := c.startLocked(e)
		c.mu.Unlock()
		val, at = c.run(e, f, compute)
		return val, at, false
	}
}

// entryLocked returns key's entry, adding it (after evicting the least
// recently asked past costCacheMax) when missing. Caller holds c.mu.
func (c *costCache[T]) entryLocked(key string) *costEntry[T] {
	if e := c.entries[key]; e != nil {
		return e
	}
	if c.entries == nil {
		c.entries = make(map[string]*costEntry[T])
	}
	for len(c.entries) >= costCacheMax {
		oldest := ""
		for k, e := range c.entries {
			if oldest == "" || e.used.Before(c.entries[oldest].used) {
				oldest = k
			}
		}
		delete(c.entries, oldest)
	}
	e := &costEntry[T]{}
	c.entries[key] = e
	return e
}

// startLocked opens a computation on e. Caller holds c.mu.
func (c *costCache[T]) startLocked(e *costEntry[T]) chan struct{} {
	e.flight = make(chan struct{})
	return e.flight
}

// run computes e's report and ends flight f, also when compute panics (the
// value held is then kept). A landed report is saved in the background.
func (c *costCache[T]) run(e *costEntry[T], f chan struct{}, compute func() T) (T, time.Time) {
	begun := c.clock()
	defer func() {
		c.mu.Lock()
		e.flight = nil
		c.mu.Unlock()
		close(f)
	}()
	v := compute()
	c.mu.Lock()
	e.val, e.at = v, begun
	c.saveLocked()
	c.mu.Unlock()
	return v, begun
}

// saveLocked saves every report in the background; saves asked while one
// runs fold into one more. Caller holds c.mu.
func (c *costCache[T]) saveLocked() {
	if c.st == nil {
		return
	}
	c.dirty = true
	if c.saving {
		return
	}
	c.saving = true
	c.bg.Add(1)
	go func() {
		defer c.bg.Done()
		for {
			c.mu.Lock()
			if !c.dirty {
				c.saving = false
				c.mu.Unlock()
				return
			}
			c.dirty = false
			saved := make(map[string]savedCostReport[T], len(c.entries))
			for k, e := range c.entries {
				if !e.at.IsZero() {
					saved[k] = savedCostReport[T]{At: e.at, Report: e.val}
				}
			}
			c.mu.Unlock()
			body, err := json.Marshal(saved)
			if err != nil {
				log.Printf("api: save cost reports: %v", err)
				continue
			}
			c.st.PutScanCache(c.saveAs, body, time.Now())
		}
	}()
}

// load restores the saved reports once, before the first request is served.
func (c *costCache[T]) load() {
	c.loadOnce.Do(func() {
		if c.st == nil {
			return
		}
		body, _, ok := c.st.ScanCache(c.saveAs)
		if !ok {
			return
		}
		var saved map[string]savedCostReport[T]
		if err := json.Unmarshal(body, &saved); err != nil {
			log.Printf("api: restore cost reports: %v", err)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		for k, s := range saved {
			if s.At.IsZero() || c.entries[k] != nil || len(c.entries) >= costCacheMax {
				continue
			}
			if c.entries == nil {
				c.entries = make(map[string]*costEntry[T])
			}
			c.entries[k] = &costEntry[T]{val: s.Report, at: s.At}
		}
	})
}
