package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// The full operator mute loop: POST /mute persists the pair AND acknowledges
// existing flags of that rule citing that host — the exact complaint ("ignore
// this rule 100 times, nothing happened") closed at the source.
func TestMuteFlowAcknowledgesExistingFlags(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir+"/e.db", dir+"/e.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.PutFlag(flagFor("f1", "sensitive-read-then-connect", "then connected to localhost:62381 at T"))
	st.PutFlag(flagFor("f2", "sensitive-read-then-connect", "then connected to 127.0.0.1:777 at T"))
	st.PutFlag(flagFor("f3", "sensitive-read-then-connect", "then connected to api.example.com:443 at T"))

	mutes := correlate.NewMuteStore(dir + "/muted.json")
	a := New(dir+"/d.sock", st, nil, nil)
	a.SetMute(correlate.New(nil, nil, config.Config{}), mutes) // correlator nil-safe? use New(nil)
	if a.mutes == nil {
		t.Fatal("mute store not set")
	}
	_ = strings.TrimSpace("")
	// Gate disabled in unit tests (checker nil) — the handler runs directly.
	h := a.buildMux()

	req := httptest.NewRequest("POST", "/mute", strings.NewReader(`{"rule":"sensitive-read-then-connect","host":"localhost"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("mute POST: %d %s", w.Code, w.Body.String())
	}
	for _, id := range []string{"f1", "f2"} {
		got, ok := st.GetFlag(id)
		if !ok || !got.Acknowledged {
			t.Fatalf("flag %s must be acknowledged by the mute (localhost alias family)", id)
		}
	}
	got3, _ := st.GetFlag("f3")
	if got3.Acknowledged {
		t.Fatal("f3 (different host) must stay unacknowledged")
	}
}

func flagFor(id, rule, evidence string) model.Flag {
	return model.Flag{ID: id, Rule: rule, Severity: 3, PID: 7, Agent: "cursor", Evidence: []string{evidence}}
}
