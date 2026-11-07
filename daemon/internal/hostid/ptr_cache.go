package hostid

import (
	"container/list"
	"sync"
)

// Keep recent endpoint names without retaining the daemon's entire IP history.
const maxPTRCacheEntries = 1024

type ptrValue struct {
	ip    string
	entry ptrEntry
}

type ptrLRU struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   list.List
}

func (c *ptrLRU) Load(ip string) (ptrEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[ip]; e != nil {
		c.order.MoveToFront(e)
		return e.Value.(ptrValue).entry, true
	}
	return ptrEntry{}, false
}

func (c *ptrLRU) Store(ip string, entry ptrEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[ip]; e != nil {
		e.Value = ptrValue{ip, entry}
		c.order.MoveToFront(e)
		return
	}
	if c.entries == nil {
		c.entries = map[string]*list.Element{}
	}
	if len(c.entries) >= maxPTRCacheEntries {
		oldest := c.order.Back()
		delete(c.entries, oldest.Value.(ptrValue).ip)
		c.order.Remove(oldest)
	}
	c.entries[ip] = c.order.PushFront(ptrValue{ip, entry})
}

func (c *ptrLRU) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.order.Init()
}
