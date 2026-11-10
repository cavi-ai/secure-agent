package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/inference"
	"net/http/httptest"
	"testing"
)

func TestLocalInferenceIsReadOnlyAndOutsideAgentAccess(t *testing.T) {
	a := newTestAPI(Deps{Store: testStore(t), Inference: inference.New()})
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/local-inference", 200}, {"POST", "/local-inference", 405}, {"GET", "/local-inference?prompt=x", 400}} {
		w := httptest.NewRecorder()
		a.handleLocalInference(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if !apiroutes.IsNoAgent("/local-inference") || !apiroutes.ConsoleAllowed("GET", "/local-inference") {
		t.Fatal("local inference lacks the owner/console no-agent gate")
	}
}
