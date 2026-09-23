package api

// Every list endpoint must emit [] — never null — on an empty store. A nil
// Go slice encodes as null, which crashes strict decoders (Swift Codable:
// "The data couldn't be read because it is missing") — the menubar's process
// transcript sheet died on exactly this for /events?pid= with zero events.
import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
)

func TestListEndpointsEmitEmptyArrayNeverNull(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	a.correlator = nil
	a.mutes = correlate.NewMuteStore(filepath.Join(t.TempDir(), "muted.json"))
	mux := a.buildMux()

	paths := []string{
		"/flags",
		"/events",
		"/events?pid=79077&limit=300", // the exact failing call
		"/incidents",
		"/audit",
		"/stats/rollup",
		"/mute",
		"/allowlist/suggestions",
		"/egress/uninspected",
		"/guard/rules",
		"/guard/path-allow",
		"/guard/pending",
	}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body := strings.TrimSpace(rec.Body.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d (body %q)", path, rec.Code, body)
		}
		if body == "null" || !strings.HasPrefix(body, "[") {
			t.Fatalf("%s: body = %q — must be [] (never null)", path, body)
		}
	}
}

// Object endpoints carry their lists in a field; /costs rows must be [] too.
func TestCostsRowsEmitEmptyArrayNeverNull(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/costs", nil))
	body := strings.TrimSpace(rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("/costs: status %d (body %q)", rec.Code, body)
	}
	if !strings.Contains(body, `"rows":[]`) {
		t.Fatalf("/costs: body = %q — rows must be [] (never null)", body)
	}
}
