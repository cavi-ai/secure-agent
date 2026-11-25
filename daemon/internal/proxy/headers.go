package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/injection"
)

// scrubResponseHeaders runs the injection detector over every response header
// value, through the same normalized views as bodies, publishes a hit naming
// each injected header and deletes it before the response is written. Nothing
// a client relies on carries injection text in a header; other headers pass
// untouched.
func (ps *ProxyServer) scrubResponseHeaders(h http.Header, host string) {
	for name, values := range h {
		for _, v := range values {
			if rule, snippet, found := detectInjection(v); found {
				ps.publishHit(host, fmt.Sprintf("proxy-prompt-injection:%s — header %s: %q", rule, name, snippet))
				h.Del(name)
				break
			}
		}
	}
}

func detectInjection(text string) (rule, snippet string, found bool) {
	for _, view := range firewall.Normalize([]byte(text)) {
		if rule, snippet, found = injection.DetectWithSnippet(view); found {
			return rule, snippet, true
		}
	}
	return "", "", false
}

// stripProxyRequestHeaders removes the proxy's own credentials from a request
// before it goes upstream. With hopByHop it also removes the hop-by-hop headers
// and every header named in Connection; tunneled requests pass false so
// Connection and Upgrade reach the upstream.
func stripProxyRequestHeaders(h http.Header, hopByHop bool) {
	if hopByHop {
		for _, v := range h.Values("Connection") {
			for _, name := range strings.Split(v, ",") {
				if name = strings.TrimSpace(name); name != "" {
					h.Del(name)
				}
			}
		}
		for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
			h.Del(name)
		}
	}
	h.Del("Proxy-Authorization")
	h.Del("X-SecureAgent-Proxy-Token")
}
