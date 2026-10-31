package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/taint"
)

// SetEgressGate installs the check every routed request passes before it is
// tunneled, decrypted or forwarded, and the prompt it raises in prompt or
// session mode (nil denies those). Call before Serve.
func (ps *ProxyServer) SetEgressGate(gate func(ctx context.Context, remoteAddr, target string) taint.Verdict,
	ask func(ctx context.Context, v taint.Verdict) bool) {
	ps.egressGate = gate
	ps.egressAsk = ask
}

// egressRefused runs the egress gate for r in its mode: deny refuses, prompt
// and session ask the user, monitor records the connection and lets it pass.
// A CONNECT is decided once for the whole tunnel; a plain request on a
// keep-alive connection, per request.
func (ps *ProxyServer) egressRefused(r *http.Request) (string, bool) {
	if ps.egressGate == nil {
		return "", false
	}
	target := r.Host
	if r.Method != http.MethodConnect && r.URL.Host != "" {
		target = r.URL.Host
	}
	v := ps.egressGate(r.Context(), r.RemoteAddr, target)
	if v.Mode == "" {
		return "", false
	}
	refused := v.Blocked()
	if v.Asks() {
		refused = ps.egressAsk == nil || !ps.egressAsk(r.Context(), v)
		if !refused {
			return "", false
		}
	}
	prefix := "proxy-untrusted-egress: "
	if !refused {
		prefix = "proxy-untrusted-egress-monitored: "
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
		Detail:     prefix + v.Detail,
	})
	return prefix + v.Detail, refused
}
