package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"net/http/httptest"
	"testing"
)

func TestSessionsReturnsUnavailableOnReadFailure(t *testing.T) {
	s, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{Store: s})
	s.Close()
	r := httptest.NewRecorder()
	a.handleSessions(r, httptest.NewRequest("GET", "/sessions", nil))
	if r.Code != 503 {
		t.Fatalf("closed database returned %d: %s", r.Code, r.Body.String())
	}
	r = httptest.NewRecorder()
	a.handleSnapshot(r, httptest.NewRequest("GET", "/snapshot", nil))
	if r.Code != 503 {
		t.Fatalf("failed snapshot read returned %d", r.Code)
	}
}
