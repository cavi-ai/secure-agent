package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagsEndpointHonorsNanosecondSince(t *testing.T) {
	st := testStore(t)
	cutoff := "2026-10-11T13:00:00.123456789+01:00"
	at, err := time.Parse(time.RFC3339Nano, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id string
		ts time.Time
	}{{"before", at.Add(-time.Nanosecond)}, {"at", at}, {"after", at.Add(time.Nanosecond)}} {
		if _, err := st.PutFlag(model.Flag{ID: row.id, Rule: "keychain-access", Severity: 3, TS: row.ts}); err != nil {
			t.Fatal(err)
		}
	}
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	w := httptest.NewRecorder()
	a.handleFlags(w, httptest.NewRequest(http.MethodGet, "/flags?since="+url.QueryEscape(cutoff), nil))
	var flags []model.Flag
	if err := json.Unmarshal(w.Body.Bytes(), &flags); err != nil {
		t.Fatalf("decode flags: %v body=%s", err, w.Body.String())
	}
	if w.Code != http.StatusOK || len(flags) != 2 || flags[0].ID != "after" || flags[1].ID != "at" {
		t.Fatalf("cutoff response: status=%d flags=%+v", w.Code, flags)
	}
}
