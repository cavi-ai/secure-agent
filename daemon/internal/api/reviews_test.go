package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestReviewRoutesAndRevisionConflict(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	a.store.UpsertSession(model.Session{ID: "session", Confidence: model.ConfHook})
	at := time.Now().UTC()
	f := model.Flag{ID: "source", Rule: readConnectRule, SessionID: "session", Severity: 3, TS: at, PID: 42, Agent: "codex", Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials", Sub: "sensitive read", PID: 42, TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
	a.store.PutFlag(f)
	mux := a.buildMux()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/reviews", nil))
	var page store.ReviewPage
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &page) != nil || len(page.Reviews) != 1 {
		t.Fatalf("review route=%d %s", rr.Code, rr.Body.String())
	}
	r := page.Reviews[0]
	if groups := attentionGroups(a); len(groups) != 0 {
		t.Fatalf("non-critical review entered Home decisions: %+v", groups)
	}
	request := func(rev int64) *httptest.ResponseRecorder {
		b, _ := json.Marshal(model.ReviewDecisionRequest{ID: r.ID, Revision: rev, Action: "acknowledge"})
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, httptest.NewRequest("POST", "/reviews/decision", bytes.NewReader(b)))
		return out
	}
	if got := request(r.Revision); got.Code != 200 {
		t.Fatalf("decision=%d %s", got.Code, got.Body.String())
	}
	f.ID = "stronger"
	f.Evidence[0].Sub = "agent tool read"
	a.store.PutFlag(f)
	if err := a.store.PutIncident(model.IncidentReport{ID: "linked", FlagID: f.ID, Rule: f.Rule, SessionID: f.SessionID, Timestamp: at, Risk: model.RiskCritical}); err != nil {
		t.Fatal(err)
	}
	if got := request(r.Revision); got.Code != 409 {
		t.Fatalf("stale revision=%d %s", got.Code, got.Body.String())
	}
	var items []AttentionItem
	for _, g := range attentionGroups(a) {
		items = append(items, g.Items...)
	}
	if len(items) != 1 || items[0].Kind != "review" {
		t.Fatalf("attention duplicated members: %+v", items)
	}
	if items[0].Review == nil || len(items[0].Review.IncidentIDs) != 1 {
		t.Fatalf("review lost report link: %+v", items)
	}
	for _, path := range []string{"/reviews", "/reviews/decision"} {
		if !apiroutes.ConsoleAllowed("GET", path) {
			t.Fatalf("console route missing: %s", path)
		}
	}
	if !apiroutes.IsMutation("POST", "/reviews/decision") {
		t.Fatal("decision not protected as a mutation")
	}
}
