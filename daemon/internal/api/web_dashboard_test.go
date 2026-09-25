package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The console's <link rel="icon"> must resolve under the same embedded
// filesystem the dashboard route serves (relative, so it lands under
// /dashboard/), and must come back as an image the browser will actually
// use as a favicon.
func TestDashboardServesDeclaredFavicon(t *testing.T) {
	h := DashboardHandler()
	if h == nil {
		t.Fatal("DashboardHandler() returned nil")
	}
	indexRec := httptest.NewRecorder()
	h.ServeHTTP(indexRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if indexRec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", indexRec.Code)
	}
	body := indexRec.Body.String()
	m := regexp.MustCompile(`<link rel="icon" href="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("index.html has no <link rel=\"icon\"> in <head>")
	}
	href := m[1]
	if strings.HasPrefix(href, "/") || strings.Contains(href, "://") {
		t.Fatalf("favicon href %q is not relative under /dashboard/", href)
	}

	iconRec := httptest.NewRecorder()
	h.ServeHTTP(iconRec, httptest.NewRequest(http.MethodGet, "/"+href, nil))
	if iconRec.Code != http.StatusOK {
		t.Fatalf("GET /%s = %d, want 200", href, iconRec.Code)
	}
	ct := iconRec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "image/") {
		t.Fatalf("favicon %s content-type = %q, want an image/* type", href, ct)
	}
}

// The dashboard CSP is script-src 'self': an inline <script> is silently
// dropped, so the pre-paint theme choice must ship as an external file, not
// inline markup in index.html.
func TestIndexHasNoInlineScript(t *testing.T) {
	h := DashboardHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, m := range regexp.MustCompile(`<script(\s[^>]*)?>`).FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[1], "src=") {
			t.Fatalf("index.html has an inline <script> tag (CSP script-src 'self' drops it): %q", m[0])
		}
	}
}
