package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
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
	a := newTestAPI(dir+"/d.sock", st, nil, nil)
	a.correlator = correlate.New(nil, nil, config.Config{})
	a.mutes = mutes // correlator nil-safe? use New(nil)
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

// POST /mute with an agent persists the scoped mute, acknowledges only that
// agent's open flags, lists it with its agent, and DELETE with the agent
// removes it.
func TestMuteAgentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir+"/e.db", "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.PutFlag(model.Flag{ID: "k1", Rule: "keychain-access", Severity: 1, PID: 7, Agent: "codex"})
	st.PutFlag(model.Flag{ID: "k2", Rule: "keychain-access", Severity: 1, PID: 9, Agent: "claude"})
	mutes := correlate.NewMuteStore(dir + "/muted.json")
	a := newTestAPI(dir+"/d.sock", st, nil, nil)
	a.mutes = mutes
	h := a.buildMux()
	do := func(method, target, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader(body)))
		return w
	}

	if w := do("POST", "/mute", `{"rule":"keychain-access","host":"*","agent":"codex"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"agent":"codex"`) {
		t.Fatalf("mute POST: %d %s", w.Code, w.Body.String())
	}
	if !mutes.Muted("keychain-access", "*", "codex") || mutes.Muted("keychain-access", "*", "claude") {
		t.Fatal("the mute must cover codex only")
	}
	if f, _ := st.GetFlag("k1"); !f.Acknowledged {
		t.Fatal("codex flag must be acknowledged")
	}
	if f, _ := st.GetFlag("k2"); f.Acknowledged {
		t.Fatal("claude flag must stay open")
	}
	if w := do("GET", "/mute", ""); !strings.Contains(w.Body.String(), `{"rule":"keychain-access","host":"*","agent":"codex"}`) {
		t.Fatalf("mute list = %s", w.Body.String())
	}
	if w := do("POST", "/mute", `{"rule":"keychain-access","host":"*","agent":"bad/agent"}`); w.Code != 400 {
		t.Fatalf("invalid agent: %d, want 400", w.Code)
	}
	if w := do("DELETE", "/mute?rule=keychain-access&host=*&agent=codex", ""); w.Code != 200 {
		t.Fatalf("mute DELETE: %d %s", w.Code, w.Body.String())
	}
	if len(mutes.Load()) != 0 {
		t.Fatalf("mutes after DELETE = %+v", mutes.Load())
	}
}

func flagFor(id, rule, evidence string) model.Flag {
	return model.Flag{ID: id, Rule: rule, Severity: 3, PID: 7, Agent: "cursor", Evidence: model.EvidenceFromStrings(evidence)}
}

// Acknowledge is idempotent and validated at the API layer: a second ack
// returns ok with acknowledged=true→false semantics preserved (already-acked
// flags answer acknowledged=false because RowsAffected=0 — the client treats
// both as success), and malformed IDs are rejected before touching the store.
func TestFlagAcknowledgeEndpoint(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir+"/e.db", dir+"/e.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.PutFlag(flagFor("valid-id.1", "sensitive-read-then-connect", "then connected to localhost:80 at T"))

	a := newTestAPI(dir+"/d.sock", st, nil, nil)
	h := a.buildMux()

	ack := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/flags/acknowledge",
			strings.NewReader(`{"flag_id":"`+id+`"}`))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := ack("valid-id.1"); w.Code != 200 {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}
	got, ok := st.GetFlag("valid-id.1")
	if !ok || !got.Acknowledged {
		t.Fatal("flag must be acknowledged after first ack")
	}
	// Idempotent: second ack succeeds (200) — RowsAffected=0 → acknowledged=false
	// in the response, but the DB state is unchanged and the call is not an error.
	if w := ack("valid-id.1"); w.Code != 200 {
		t.Fatalf("second ack must be a 200 no-op: %d", w.Code)
	}
	// Malformed ID rejected before touching the store.
	if w := ack("../evil"); w.Code != 400 {
		t.Fatalf("malformed id must 400; got %d", w.Code)
	}
	// Unknown id: 200 with acknowledged=false (no state change, idempotent).
	if w := ack("does-not-exist"); w.Code != 200 {
		t.Fatalf("unknown id ack should 200; got %d", w.Code)
	}
}
