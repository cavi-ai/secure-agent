package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// /debug/pprof/ is served to the owner on the unix socket, refused for an
// agent peer, and absent from the proxy listener's console handler.
func TestPprofOwnerOnly(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_pprof_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	var asAgent atomic.Bool
	selfPID := int32(os.Getpid())
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, func() map[int32]struct{} {
		if asAgent.Load() {
			return map[int32]struct{}{selfPID: {}}
		}
		return nil
	})
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	get := func(path string) int {
		t.Helper()
		cl := unixClient(sock)
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := cl.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, p := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/goroutine?debug=1"} {
		if code := get(p); code != http.StatusOK {
			t.Fatalf("owner GET %s: %d, want 200", p, code)
		}
	}
	asAgent.Store(true)
	for _, p := range []string{"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof"} {
		if code := get(p); code != http.StatusForbidden {
			t.Fatalf("agent GET %s: %d, want 403", p, code)
		}
	}

	for _, r := range []role{roleNone, roleForeign, roleAgent} {
		if a.authorize(r, http.MethodGet, "/debug/pprof/heap") {
			t.Errorf("role %s authorized for /debug/pprof/heap", r)
		}
	}
	for _, r := range []role{roleOwner, roleUI} {
		if !a.authorize(r, http.MethodGet, "/debug/pprof/heap") {
			t.Errorf("role %s refused /debug/pprof/heap", r)
		}
	}

	rec := httptest.NewRecorder()
	a.ConsoleHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("console handler GET /debug/pprof/: %d, want 404 (never registered off the socket)", rec.Code)
	}
}
