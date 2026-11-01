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

// SocketConnection is a process's remote TCP endpoint. It allows callers to
// implement SocketLister, including deterministic integration fixtures.
type SocketConnection = connKey

type SocketLister interface {
	SocketsFor(pid int32) []SocketConnection
}

type NetSampler struct {
	bus      *bus.Bus
	tagger   *agents.Tagger
	lister   SocketLister
	interval time.Duration

	// OnProduce, when set, is called after any conn event is published — the
	// supervisor's coverage heartbeat ("running" ≠ "seeing anything").
	OnProduce func()

	mu       sync.Mutex
	dnsCache map[string]string
	// inflight holds the addresses whose reverse lookup has not finished.
	inflight map[string]bool
	// lookupAddr is the reverse resolver; tests replace it.
	lookupAddr func(context.Context, string) ([]string, error)
	// conns are the sampled connections, owned by Run's loop.
	conns map[connKey]liveConn
	// dnsSem bounds concurrent reverse lookups; lookups run off the sampling
	// hot path (see resolveHost) so a slow/absent resolver never stalls event
	// delivery.
	dnsSem chan struct{}
}

func NewNetSampler(b *bus.Bus, tagger *agents.Tagger, interval time.Duration, lister SocketLister) *NetSampler {
	if lister == nil {
		lister = NewSocketLister()
	}
	return &NetSampler{
		bus:        b,
		tagger:     tagger,
		lister:     lister,
		interval:   interval,
		dnsCache:   make(map[string]string),
		inflight:   make(map[string]bool),
		lookupAddr: net.DefaultResolver.LookupAddr,
		conns:      make(map[connKey]liveConn),
		dnsSem:     make(chan struct{}, 4),
	}
}

// isLoopbackHost reports whether a socket's remote endpoint is loopback
// (127.0.0.0/8 or ::1). Loopback churn — dev servers, local model servers,
// the daemon's own socket — is machine-local noise, not egress: recording it
// floods the event store with socket churn and drowns real connections out of
// the count-based retention window.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (ns *NetSampler) Run(ctx context.Context) error {
	ticker := time.NewTicker(ns.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			if ns.step(now) > 0 && ns.OnProduce != nil {
				ns.OnProduce()
			}
		}
	}
}

// liveConn is one sampled connection, keyed by its address: the host its
// open event named (the resolved name, else the address), when it was first
// sampled, and whether its open event went out.
type liveConn struct {
	host   string
	since  time.Time
	opened bool
}

// step samples the agents' sockets once and publishes an open for each new
// connection and a close for each one gone; it returns how many events it
// published. A connection is keyed by its address, so a name that resolves
// later does not read as the connection closing and reopening. The first
// connection to an address the resolver has not answered for waits one
// sample, so its open can name the host; it is stamped when first sampled
// and published even if it closed meanwhile.
func (ns *NetSampler) step(now time.Time) int {
	cur := map[connKey]bool{}
	if ns.tagger.Any() {
		for _, s := range ns.lister.SocketsFor(-1) {
			if isLoopbackHost(s.Host) {
				continue // loopback is not egress; see isLoopbackHost
			}
			if _, isAgent := ns.tagger.Tag(s.PID); isAgent {
				cur[s] = true
			}
		}
	}
	published := 0
	publish := func(kind event.Kind, k connKey, host string, at time.Time) {
		ns.bus.Publish(event.Event{Kind: kind, TS: at, PID: k.PID, RemoteHost: host, RemotePort: k.Port})
		published++
	}
	for k := range cur {
		c, seen := ns.conns[k]
		switch {
		case !seen:
			host, answered := ns.resolveHost(k.Host)
			c = liveConn{host: host, since: now, opened: answered}
			if answered {
				publish(event.KindConnOpen, k, host, now)
			}
			ns.conns[k] = c
		case !c.opened:
			c.host, _ = ns.resolveHost(k.Host)
			c.opened = true
			publish(event.KindConnOpen, k, c.host, c.since)
			ns.conns[k] = c
		}
	}
	for k, c := range ns.conns {
		if cur[k] {
			continue
		}
		if !c.opened {
			c.host, _ = ns.resolveHost(k.Host)
			publish(event.KindConnOpen, k, c.host, c.since)
		}
		publish(event.KindConnClose, k, c.host, now)
		delete(ns.conns, k)
	}
	return published
}

// (removed) getTaggedPIDs had no callers — tagged-agent filtering happens
// inline in Run via tagger.Tag per socket.

// resolveHost returns the cached name for an IP, or the IP itself immediately
// while an async lookup (deadline-bounded, concurrency-capped) fills the cache
// for the next sample; answered is false while that lookup has not finished.
// The previous design called net.LookupAddr inline with no timeout: a slow or
// absent PTR resolver stalled the entire sampler loop (and with it, all conn
// open/close events) for seconds at a time.
func (ns *NetSampler) resolveHost(ipOrHost string) (host string, answered bool) {
	if ipOrHost == "" {
		return "", true
	}
	if ip := net.ParseIP(ipOrHost); ip == nil {
		return ipOrHost, true // already a hostname
	}

	ns.mu.Lock()
	if name, ok := ns.dnsCache[ipOrHost]; ok {
		answered := !ns.inflight[ipOrHost]
		ns.mu.Unlock()
		return name, answered
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
		return ipOrHost, true // lookups saturated; the negative entry still bounds retries
	}
	ns.mu.Lock()
	ns.inflight[ipOrHost] = true
	ns.mu.Unlock()
	go func() {
		defer func() { <-ns.dnsSem }()
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		defer cancel()
		res := ipOrHost
		if names, err := ns.lookupAddr(ctx, ipOrHost); err == nil && len(names) > 0 {
			res = strings.TrimSuffix(names[0], ".")
		}
		ns.mu.Lock()
		ns.dnsCache[ipOrHost] = res
		delete(ns.inflight, ipOrHost)
		ns.mu.Unlock()
	}()

	return ipOrHost, false
}
