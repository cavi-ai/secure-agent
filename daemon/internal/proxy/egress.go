package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/taint"
)

// SetEgressGate installs the check every routed request passes before it is
// tunneled, decrypted or forwarded. Call before Serve.
func (ps *ProxyServer) SetEgressGate(gate func(ctx context.Context, remoteAddr, target string) taint.Verdict) {
	ps.egressGate = gate
}

// egressRefused runs the egress gate for r and publishes a refusal with the
// client process and session it names. A CONNECT is decided once for the
// whole tunnel; a plain request on a keep-alive connection, per request.
func (ps *ProxyServer) egressRefused(r *http.Request) (string, bool) {
	if ps.egressGate == nil {
		return "", false
	}
	target := r.Host
	if r.Method != http.MethodConnect && r.URL.Host != "" {
		target = r.URL.Host
	}
	v := ps.egressGate(r.Context(), r.RemoteAddr, target)
	if !v.Blocked {
		return "", false
	}
	host, port := splitTarget(target)
	if r.Method != http.MethodConnect && r.URL.Scheme == "http" && port == 443 && host == target {
		port = 80
	}
	ps.bus.Publish(event.Event{
		Kind:       event.KindProxyHit,
		TS:         time.Now(),
		PID:        v.PID,
		SessionID:  v.SessionID,
		RemoteHost: host,
		RemotePort: port,
		Detail:     v.Detail,
	})
	return v.Detail, true
}
