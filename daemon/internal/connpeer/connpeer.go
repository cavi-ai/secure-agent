// Package connpeer remembers, per accepted TCP connection, which process
// holds its client end, so a keep-alive connection is looked up once.
package connpeer

import (
	"context"
	"net"
	"sync"
)

type cacheKey struct{}

type cache struct {
	mu  sync.Mutex
	pid int32
	ok  bool
}

// WithCache is an http.Server ConnContext: every connection gets its own
// empty cache.
func WithCache(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, cacheKey{}, &cache{})
}

// PID returns the client pid of the connection ctx belongs to. A successful
// lookup is kept for the connection's lifetime (the process holding a
// connection's client end does not change); a failed one is retried on the
// next request. Without a cache in ctx it calls lookup every time.
func PID(ctx context.Context, remoteAddr string, lookup func(string) (int32, error)) (int32, error) {
	c, _ := ctx.Value(cacheKey{}).(*cache)
	if c == nil {
		return lookup(remoteAddr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok {
		return c.pid, nil
	}
	pid, err := lookup(remoteAddr)
	if err == nil {
		c.pid, c.ok = pid, true
	}
	return pid, err
}
