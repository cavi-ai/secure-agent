package api

import (
	"bytes"
	"image/png"
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

// A revalidating browser gets a 304 for an unchanged asset, and the tag
// follows the file's content.
func TestDashboardAssetsRevalidateByContent(t *testing.T) {
	h := DashboardHandler()
	tags := map[string]string{}
	for _, p := range []string{"/", "/app.js", "/style.css", "/brand-icon.png"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		tag := rec.Header().Get("ETag")
		if rec.Code != http.StatusOK || tag == "" {
			t.Fatalf("GET %s = %d with ETag %q", p, rec.Code, tag)
		}
		tags[p] = tag
		again := httptest.NewRequest(http.MethodGet, p, nil)
		again.Header.Set("If-None-Match", tag)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, again)
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Fatalf("revalidated GET %s = %d with %d bytes, want 304", p, rec.Code, rec.Body.Len())
		}
	}
	if tags["/app.js"] == tags["/style.css"] {
		t.Fatal("different files share an ETag")
	}
}

// The console shows the brand mark at 44 px; the embedded file stays small.
func TestBrandIconIsSizedForTheConsole(t *testing.T) {
	b, err := webFS.ReadFile("web_dist/brand-icon.png")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 64<<10 || cfg.Width > 256 || cfg.Height > 256 {
		t.Fatalf("brand-icon.png is %dx%d, %d bytes", cfg.Width, cfg.Height, len(b))
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
