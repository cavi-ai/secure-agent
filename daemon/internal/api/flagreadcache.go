package api

import (
	"slices"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// flagReadCacheSize bounds the filters kept for one generation: posture and
// the snapshot read two, and the windows move once a minute.
const flagReadCacheSize = 8

// flagReadCache reuses the flag reads the pattern and routine views repeat
// (every snapshot and posture recompute) until a flag or advisor verdict is
// written. Entries all belong to one store generation.
type flagReadCache struct {
	mu      sync.Mutex
	gen     uint64
	entries map[store.FlagFilter][]model.Flag
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
