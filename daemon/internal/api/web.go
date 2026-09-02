package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web_dist/*
var webFS embed.FS

// DashboardHandler exposes the embedded console filesystem so other listeners
// (the proxy's loopback HTTP port) can serve the same canonical assets.
func DashboardHandler() http.Handler {
	sub, err := fs.Sub(webFS, "web_dist")
	if err != nil {
		return nil
	}
	return http.FileServer(http.FS(sub))
}

func (a *API) setupWebDashboard(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "web_dist")
	if err != nil {
		return
	}
	h := http.StripPrefix("/dashboard/", http.FileServer(http.FS(sub)))
	mux.Handle("/dashboard/", securityHeaders(h))
}

// securityHeaders wraps a handler with the browser-hardening header set shared
// with the proxy's dashboard route.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
