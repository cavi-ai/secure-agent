package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
)

//go:embed web_dist/*
var webFS embed.FS

// DashboardHandler exposes the embedded console filesystem so other listeners
// (the proxy's loopback HTTP port) can serve the same canonical assets.
func DashboardHandler() http.Handler {
	h, err := consoleFiles()
	if err != nil {
		return nil
	}
	return h
}

func (a *API) setupWebDashboard(mux *http.ServeMux) {
	h, err := consoleFiles()
	if err != nil {
		return
	}
	mux.Handle("/dashboard/", securityHeaders(http.StripPrefix("/dashboard/", h)))
}

// consoleFiles serves the embedded console with a content-hash ETag on each
// file. embed.FS carries no modification times, so the ETag is what lets a
// revalidating browser get a 304 instead of every asset again.
func consoleFiles() (http.Handler, error) {
	sub, err := fs.Sub(webFS, "web_dist")
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	err = fs.WalkDir(sub, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(sub, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		tags["/"+name] = `"` + hex.EncodeToString(sum[:12]) + `"`
		return nil
	})
	if err != nil {
		return nil, err
	}
	tags["/"] = tags["/index.html"]
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag, ok := tags[path.Clean("/"+r.URL.Path)]; ok {
			w.Header().Set("ETag", tag)
		}
		files.ServeHTTP(w, r)
	}), nil
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
		// no-cache (not no-store): the browser must revalidate every load, so
		// an upgrade can never leave a stale index.html paired with a new
		// app.js (or vice versa) — the "dashboard doesn't load after update"
		// failure mode. The content-hash ETag keeps revalidation a 304.
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}
