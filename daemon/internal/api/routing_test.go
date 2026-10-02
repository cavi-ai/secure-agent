package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRoutingClaude(t *testing.T) {
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, nil, nil)
	get := func(method string) (*httptest.ResponseRecorder, RoutingInfo) {
		rec := httptest.NewRecorder()
		a.buildMux().ServeHTTP(rec, httptest.NewRequest(method, "/routing/claude", nil))
		var info RoutingInfo
		_ = json.Unmarshal(rec.Body.Bytes(), &info)
		return rec, info
	}
	if rec, info := get(http.MethodGet); rec.Code != http.StatusOK || info.Ready || info.Reason == "" {
		t.Fatalf("unwired: %d %+v, want 200, not ready, with a reason", rec.Code, info)
	}
	want := RoutingInfo{Ready: true, Env: map[string]string{"HTTPS_PROXY": "http://inspect:t@127.0.0.1:8443"}, BashEnvPath: "/c/agent-env.sh"}
	a.routing = func() RoutingInfo { return want }
	if rec, info := get(http.MethodGet); rec.Code != http.StatusOK || !reflect.DeepEqual(info, want) {
		t.Fatalf("wired: %d %+v, want %+v", rec.Code, info, want)
	}
	if rec, _ := get(http.MethodPost); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", rec.Code)
	}
}
