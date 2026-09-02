package proxy

import (
	"net/http"
)

// The web console assets are embedded by the api package; to avoid a duplicate
// embed (and an import cycle), the api package registers its handler here at
// startup. When unset, /dashboard/ answers 404 rather than proxying.
var dashboardHandler http.Handler

// SetDashboardHandler wires the embedded console filesystem from the api
// package, keeping the asset source canonical in one place.
func SetDashboardHandler(h http.Handler) { dashboardHandler = h }

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	dashboardHeaders(w)
	if dashboardHandler == nil {
		http.Error(w, "dashboard not available", http.StatusNotFound)
		return
	}
	// Normalize "/dashboard" to "/dashboard/" so relative asset paths resolve.
	if r.URL.Path == "/dashboard" {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
		return
	}
	dashboardHandler.ServeHTTP(w, r)
}
