package collect

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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
			curSnapshot := make(map[connKey]struct{})
			// Sample active sockets and filter against tagged agent process trees
			allSocks := ns.lister.SocketsFor(-1)
			for _, s := range allSocks {
				if info, isAgent := ns.tagger.Tag(s.PID); isAgent {
					resolvedHost := ns.resolveHost(s.Host)
					k := connKey{PID: s.PID, Host: resolvedHost, Port: s.Port}
					curSnapshot[k] = struct{}{}
					log.Printf("netsample: found agent socket pid=%d agent=%s host=%s port=%d", s.PID, info.Name, resolvedHost, s.Port)
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

func (ns *NetSampler) getTaggedPIDs() map[int32]struct{} {
	pids := make(map[int32]struct{})
	for pid := range ns.tagger.TaggedPIDs() {
		pids[pid] = struct{}{}
	}
	return pids
}

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
	ns.mu.Unlock()

	names, err := net.LookupAddr(ipOrHost)
	res := ipOrHost
	if err == nil && len(names) > 0 {
		res = names[0]
		if res[len(res)-1] == '.' {
			res = res[:len(res)-1]
		}
	}

	ns.mu.Lock()
	if len(ns.dnsCache) < 256 {
		ns.dnsCache[ipOrHost] = res
	}
	ns.mu.Unlock()

	return res
}
