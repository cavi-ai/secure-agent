package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// The endpoint detail explains an unattributed address: identity plus the
// agents/sessions behind it. Missing ?host= is a 400, not a panic.
func TestEndpointDetail(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })

	// Zero times must serialize as omitted, never as year 0001.
	rec := httptest.NewRecorder()
	a.handleEndpointDetail(rec, httptest.NewRequest(http.MethodGet, "/egress/endpoint?host=2600:1901:0:9e23::", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var d EndpointDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Host != "2600:1901:0:9e23::" || d.Identity.Org != "Google Cloud" || d.Identity.Kind != "ipv6" {
		t.Fatalf("detail = %+v", d)
	}
	if d.FirstSeen != nil || d.LastSeen != nil {
		t.Fatalf("zero times must be omitted: first=%v last=%v", d.FirstSeen, d.LastSeen)
	}
	if d.Agents == nil || d.Sessions == nil || d.Events == nil {
		t.Fatalf("lists must be empty arrays, not null: %+v", d)
	}

	// A connection event to that host must surface in the detail.
	host := "203.0.113.7"
	st.PutEvent(event.Event{Kind: event.KindConnOpen, TS: time.Now(), SessionID: "sess-1",
		RemoteHost: host, RemotePort: 443})
	rec = httptest.NewRecorder()
	a.handleEndpointDetail(rec, httptest.NewRequest(http.MethodGet, "/egress/endpoint?host="+host, nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Events) != 1 || d.Events[0].RemotePort != 443 {
		t.Fatalf("events = %+v", d.Events)
	}

	rec = httptest.NewRecorder()
	a.handleEndpointDetail(rec, httptest.NewRequest(http.MethodGet, "/egress/endpoint", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing host code=%d, want 400", rec.Code)
	}
}

// An approved parent domain counts as an allowance for its subdomains, the
// same rule the correlator applies; a look-alike suffix does not.
func TestEndpointDetailAllowedCoversSubdomain(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	a.allowlist = correlate.NewAllowlistStore(filepath.Join(t.TempDir(), "allowlist.json"))
	if err := a.allowlist.Add("claude", "anthropic.com"); err != nil {
		t.Fatal(err)
	}
	get := func(host string) EndpointDetail {
		t.Helper()
		rec := httptest.NewRecorder()
		a.handleEndpointDetail(rec, httptest.NewRequest(http.MethodGet, "/egress/endpoint?host="+host, nil))
		var d EndpointDetail
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := get("api.anthropic.com")
	if len(d.Allowed) != 1 || d.Allowed[0].Agent != "claude" || d.Allowed[0].Host != "anthropic.com" {
		t.Fatalf("allowed = %+v, want claude via anthropic.com", d.Allowed)
	}
	if d := get("evilanthropic.com"); len(d.Allowed) != 0 {
		t.Fatalf("look-alike allowed = %+v, want none", d.Allowed)
	}
}
