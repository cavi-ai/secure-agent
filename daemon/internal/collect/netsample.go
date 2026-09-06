package collect

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

const (
	// dnsLookupTimeout bounds one reverse lookup so a hung resolver can't pin
	// a lookup goroutine forever.
	dnsLookupTimeout = 3 * time.Second
	// maxDNSCacheEntries bounds the PTR cache; on overflow it resets wholesale
	// (stale PTR data is worse than a cold cache, re-fetch is cheap).
	maxDNSCacheEntries = 512
)

type connKey struct {
	PID  int32
	Host string
	Port int
}

type SocketLister interface {
	SocketsFor(pid int32) []connKey
}

type NetSampler struct {
	bus      *bus.Bus
	tagger   *agents.Tagger
	lister   SocketLister
	interval time.Duration

	mu       sync.Mutex
	dnsCache map[string]string
	// dnsSem bounds concurrent reverse lookups; lookups run off the sampling
	// hot path (see resolveHost) so a slow/absent resolver never stalls event
	// delivery.
	dnsSem chan struct{}
}

func NewNetSampler(b *bus.Bus, tagger *agents.Tagger, interval time.Duration, lister SocketLister) *NetSampler {
	if lister == nil {
		lister = NewDarwinSocketLister()
	}
	return &NetSampler{
		bus:      b,
		tagger:   tagger,
		lister:   lister,
		interval: interval,
		dnsCache: make(map[string]string),
		dnsSem:   make(chan struct{}, 4),
	}
}

func DiffConnections(prev, cur map[connKey]struct{}) (opened, closed []connKey) {
	for k := range cur {
		if _, ok := prev[k]; !ok {
			opened = append(opened, k)
		}
	}
	for k := range prev {
		if _, ok := cur[k]; !ok {
			closed = append(closed, k)
		}
	}
	return opened, closed
}

func (ns *NetSampler) Run(ctx context.Context) error {
	ticker := time.NewTicker(ns.interval)
	defer ticker.Stop()

	prevSnapshot := make(map[connKey]struct{})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !ns.tagger.Any() {
				if len(prevSnapshot) > 0 {
					now := time.Now()
					for k := range prevSnapshot {
						ns.bus.Publish(event.Event{
							Kind:       event.KindConnClose,
							TS:         now,
							PID:        k.PID,
							RemoteHost: k.Host,
							RemotePort: k.Port,
						})
					}
					prevSnapshot = make(map[connKey]struct{})
				}
				continue
			}

			curSnapshot := make(map[connKey]struct{})
			// Sample active sockets and filter against tagged agent process trees
			allSocks := ns.lister.SocketsFor(-1)
			for _, s := range allSocks {
				if _, isAgent := ns.tagger.Tag(s.PID); isAgent {
					resolvedHost := ns.resolveHost(s.Host)
					k := connKey{PID: s.PID, Host: resolvedHost, Port: s.Port}
					curSnapshot[k] = struct{}{}
				}
			}

			opened, closed := DiffConnections(prevSnapshot, curSnapshot)

			now := time.Now()
			for _, k := range opened {
				ns.bus.Publish(event.Event{
					Kind:       event.KindConnOpen,
					TS:         now,
					PID:        k.PID,
					RemoteHost: k.Host,
					RemotePort: k.Port,
				})
			}
			for _, k := range closed {
				ns.bus.Publish(event.Event{
					Kind:       event.KindConnClose,
					TS:         now,
					PID:        k.PID,
					RemoteHost: k.Host,
					RemotePort: k.Port,
				})
			}

			prevSnapshot = curSnapshot
		}
	}
}

// (removed) getTaggedPIDs had no callers — tagged-agent filtering happens
// inline in Run via tagger.Tag per socket.

// resolveHost returns the cached name for an IP, or the IP itself immediately
// while an async lookup (deadline-bounded, concurrency-capped) fills the cache
// for the next sample. The previous design called net.LookupAddr inline with no
// timeout: a slow or absent PTR resolver stalled the entire sampler loop (and
// with it, all conn open/close events) for seconds at a time.
func (ns *NetSampler) resolveHost(ipOrHost string) string {
	if ipOrHost == "" {
		return ""
	}
	if ip := net.ParseIP(ipOrHost); ip == nil {
		return ipOrHost // already a hostname
	}

	ns.mu.Lock()
	if name, ok := ns.dnsCache[ipOrHost]; ok {
		ns.mu.Unlock()
		return name
	}
	// Optimistic negative entry so a slow resolver doesn't spawn a lookup per
	// sample for the same IP; the async lookup overwrites it with the name (or
	// re-stores the IP on failure).
	ns.dnsCache[ipOrHost] = ipOrHost
	if len(ns.dnsCache) >= maxDNSCacheEntries {
		// Wholesale reset: PTR data is cheap to re-fetch and stale entries are
		// worse than a cold cache.
		ns.dnsCache = map[string]string{ipOrHost: ipOrHost}
	}
	ns.mu.Unlock()

	select {
	case ns.dnsSem <- struct{}{}:
	default:
		return ipOrHost // lookups saturated; the negative entry still bounds retries
	}
	go func() {
		defer func() { <-ns.dnsSem }()
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		defer cancel()
		res := ipOrHost
		if names, err := net.DefaultResolver.LookupAddr(ctx, ipOrHost); err == nil && len(names) > 0 {
			res = strings.TrimSuffix(names[0], ".")
		}
		ns.mu.Lock()
		ns.dnsCache[ipOrHost] = res
		ns.mu.Unlock()
	}()

	return ipOrHost
}
