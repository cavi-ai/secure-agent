package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
)

func TestGuardResolveReceiptMatchesAnswerAndRejectsReplay(t *testing.T) {
	st := testStore(t)
	a := newTestAPI(Deps{Store: st, Guard: guard.NewBroker(time.Second)})
	id, done := guardDecisionAsync(t, a, context.Background())
	resolve := func() map[string]any {
		w := httptest.NewRecorder()
		a.handleGuardResolve(w, httptest.NewRequest("POST", "/guard/resolve", strings.NewReader(`{"id":"`+id+`","verdict":"allow","scope":"once"}`)))
		if w.Code != 200 {
			t.Fatalf("resolve: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	body := resolve()
	receipt, ok := body["receipt"].(map[string]any)
	if !ok || receipt["id"] != id || receipt["verdict"] != "allow" || receipt["scope"] != "once" || receipt["at"] == "" {
		t.Fatalf("missing matching receipt: %+v", body)
	}
	if d := <-done; d.Verdict != "allow" {
		t.Fatalf("answer changed: %+v", d)
	}
	if again := resolve(); again["resolved"] != false || again["receipt"] != nil {
		t.Fatalf("replayed receipt: %+v", again)
	}
}
