package api

import (
	"net/http"
	"net/http/pprof"
	"strings"
)

// handlePprof serves the runtime profiles under /debug/pprof/. The route is
// OwnerOnly: registered on the unix-socket mux alone and gated to the owner
// uid by the peer-role gate.
func handlePprof(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/debug/pprof/") {
	case "cmdline":
		pprof.Cmdline(w, r)
	case "profile":
		pprof.Profile(w, r)
	case "symbol":
		pprof.Symbol(w, r)
	case "trace":
		pprof.Trace(w, r)
	default:
		pprof.Index(w, r)
	}
}
