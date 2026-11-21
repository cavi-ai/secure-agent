package proxy

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func StartRouteProxyForTest(t *testing.T) (*ProxyServer, string, string) {
	t.Helper()
	return startRouteProxy(t)
}

func (ps *ProxyServer) Events() <-chan event.Event {
	return ps.bus.Subscribe()
}
