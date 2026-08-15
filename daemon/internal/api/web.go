package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web_dist/*
var webFS embed.FS

func (a *API) setupWebDashboard(mux *http.ServeMux) {
	sub, err := fs.Sub(webFS, "web_dist")
	if err != nil {
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", fileServer))
}
