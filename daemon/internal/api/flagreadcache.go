package api

import (
	"slices"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// flagReadCacheSize bounds the filters kept for one generation: posture and
// the snapshot read two, and the windows move once a minute.
const flagReadCacheSize = 8

// storeReadMaxAge bounds how long cached snapshot and posture reads serve: the
// 24 h flag window and the 30 min hook-health window then trail the clock by
// under 10 s, and dayWindow still moves only once a minute.
const storeReadMaxAge = 10 * time.Second

// flagReadCache reuses the flag reads the pattern and routine views repeat
// (every snapshot and posture recompute) until a flag or advisor verdict is
// written. Entries all belong to one store generation.
type flagReadCache struct {
	mu      sync.Mutex
	gen     uint64
	entries map[store.FlagFilter][]model.Flag

	// snapshot and posture hold the store-derived parts of those responses,
	// keyed by the store's write generation.
	snapshot genCache[snapshotReads]
	posture  genCache[posture.Inputs]
	// now is the clock of their windows and entry ages; nil means time.Now.
	now func() time.Time
}

// clock is the time snapshot and posture reads use.
func (a *API) clock() time.Time {
	if a.flagReads.now != nil {
		return a.flagReads.now()
	}
	return time.Now()
}

// genCache holds one value read at a store write generation. It serves the
// value only at that generation, under storeReadMaxAge after the read began
// and in the same dayWindow minute. Callers treat the value as read-only.
// Only values computed from store rows alone are cached, because the
// generation tracks nothing else: whatever also reads live status, the
// allowlist, expectations, mutes, the host identity cache or the price table
// is computed on every request.
type genCache[T any] struct {
	mu  sync.Mutex
	set bool
	gen uint64
	at  time.Time
	val T
}

func (c *genCache[T]) get(gen uint64, now time.Time) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	age := now.Sub(c.at)
	if !c.set || c.gen != gen || age < 0 || age >= storeReadMaxAge || !dayWindow(now).Equal(dayWindow(c.at)) {
		var zero T
		return zero, false
	}
	return c.val, true
}

// put keeps val, read from time at with gen loaded before the reads began,
// unless the cache already holds a newer generation or a later read.
func (c *genCache[T]) put(gen uint64, at time.Time, val T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set && (gen < c.gen || gen == c.gen && at.Before(c.at)) {
		return
	}
	c.set, c.gen, c.at, c.val = true, gen, at, val
}

// read returns the flags f selects. The generation is loaded before the
// query, so an entry is never tagged newer than its rows. Each caller gets its
// own slice.
func (c *flagReadCache) read(st *store.Store, f store.FlagFilter) ([]model.Flag, error) {
	gen := st.FlagGeneration()
	c.mu.Lock()
	cached, ok := c.entries[f]
	ok = ok && c.gen == gen
	c.mu.Unlock()
	if ok {
		return slices.Clone(cached), nil
	}
	flags, err := st.QueryFlags(f)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case gen < c.gen:
		// A read after a newer write already moved the cache on.
	case gen > c.gen || c.entries == nil || len(c.entries) >= flagReadCacheSize:
		c.gen, c.entries = gen, map[store.FlagFilter][]model.Flag{f: flags}
	default:
		c.entries[f] = flags
	}
	return slices.Clone(flags), nil
}

// dayWindow is the start of the 24 h window posture and the snapshot read.
// It moves once a minute so their repeated flag reads share a cached result.
func dayWindow(now time.Time) time.Time {
	return now.Add(-24 * time.Hour).Truncate(time.Minute)
}
