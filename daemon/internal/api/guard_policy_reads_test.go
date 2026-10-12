package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuardPolicyReadsDistinguishEmptyFromUnavailable(t *testing.T) {
	for _, route := range []string{"/guard/rules", "/guard/path-allow"} {
		t.Run(route, func(t *testing.T) {
			st := testStore(t)
			t.Cleanup(func() { _ = st.Close() })
			a := newTestAPI(Deps{Store: st})
			mux := a.buildMux()
			read := func() *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
				return rec
			}
			empty := read()
			if empty.Code != http.StatusOK || strings.TrimSpace(empty.Body.String()) != "[]" {
				t.Fatalf("empty policy: status=%d body=%q", empty.Code, empty.Body.String())
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			unavailable := read()
			if unavailable.Code != http.StatusServiceUnavailable {
				t.Fatalf("unavailable policy: status=%d body=%q", unavailable.Code, unavailable.Body.String())
			}
			if strings.Contains(unavailable.Body.String(), "sql:") || strings.Contains(unavailable.Body.String(), "database") {
				t.Fatalf("storage diagnostic exposed: %q", unavailable.Body.String())
			}
		})
	}
}
