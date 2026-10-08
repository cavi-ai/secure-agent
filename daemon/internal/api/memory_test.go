package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestMemoryPresenterStructuredSummaries(t *testing.T) {
	known := presentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "cloud-creds", Verdict: "allow", Scope: "always"})
	for _, want := range []string{"Cloud credentials", "Allow", "Always"} {
		if !strings.Contains(known.Title+" "+known.Detail, want) {
			t.Fatalf("known guard summary missing %q: %+v", want, known)
		}
	}
	unknown := presentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "PRIVATE_PROMPT_TEXT123", Verdict: "allow", Scope: "PRIVATE_SCOPE123"})
	if strings.Contains(fmt.Sprintf("%+v", unknown), "PRIVATE_") || !strings.Contains(unknown.Detail, "Guard rule") || strings.Contains(unknown.Detail, "Scope:") {
		t.Fatalf("unknown guard fields leaked or lost generic label: %+v", unknown)
	}
	once := presentMemoryFact(store.MemoryFact{Kind: "guard", RuleID: "cloud-creds", Verdict: "allow", Scope: "once"})
	if !strings.Contains(once.Detail, "Scope: Once") || once.Detail == known.Detail {
		t.Fatalf("allow-once and allow-always summaries are indistinguishable: once=%+v always=%+v", once, known)
	}
	resource := presentMemoryFact(store.MemoryFact{Kind: "resource", DiagnosisCodes: []string{"heavy-memory"}, RSSBytes: 4 << 30})
	if !strings.Contains(resource.Detail, "Heavy memory") || !strings.Contains(resource.Detail, "4 GiB") {
		t.Fatalf("resource summary lost measured pressure: %+v", resource)
	}
	usage := presentMemoryFact(store.MemoryFact{Kind: "activity", EventKind: event.KindModelCall, Model: "claude-sonnet-4-5", TokensIn: 1200, TokensOut: 300})
	for _, want := range []string{"1200 input", "300 output"} {
		if !strings.Contains(usage.Detail, want) {
			t.Fatalf("usage summary missing %q: %+v", want, usage)
		}
	}
	big := presentMemoryFact(store.MemoryFact{Kind: "resource", RSSBytes: math.MaxUint64})
	if !strings.Contains(big.Detail, "15.9 EiB") || strings.Contains(big.Detail, "-") {
		t.Fatalf("large RSS overflowed or disappeared: %+v", big)
	}
	bigUsage := presentMemoryFact(store.MemoryFact{Kind: "activity", EventKind: event.KindModelCall, TokensIn: math.MaxInt64, TokensOut: -1})
	if !strings.Contains(bigUsage.Detail, "9223372036854775807 input") || strings.Contains(bigUsage.Detail, "-1") {
		t.Fatalf("usage counts overflowed or exposed negative value: %+v", bigUsage)
	}
}

func TestMemoryRSSLabelFractionBoundary(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{{1126, "1.0 KiB"}, {1127, "1.1 KiB"}} {
		if got := memoryRSSLabel(tc.bytes); got != tc.want {
			t.Errorf("memoryRSSLabel(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}

func TestSessionMemoryRedaction(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	st.UpsertSession(model.Session{ID: "s1", RootPID: 100, RootStartedAt: started.Format(time.RFC3339Nano), StartedAt: started, LastSeenAt: now})
	hostile := "<script>SECRET-RAW</script>"
	identifierSecret := "PRIVATE_PROMPT_TEXT123"
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now, SessionID: "s1", Path: hostile, Detail: hostile})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s1", ToolName: identifierSecret})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now, SessionID: "s1", Model: identifierSecret})
	st.PutEvent(event.Event{Kind: event.KindToolCall, TS: now, SessionID: "s1", ToolName: "Bash"})
	st.PutEvent(event.Event{Kind: event.KindModelCall, TS: now.Add(3 * time.Nanosecond), SessionID: "s1", Model: "claude-sonnet-4-5", TokensIn: 1200, TokensOut: 300})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(time.Nanosecond), SessionID: "s1", Path: "guard-deny:cloud-creds", Detail: "secret-guard:deny"})
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(2 * time.Nanosecond), SessionID: "s1", Path: "guard-deny:cloud-creds", Detail: "secret-guard-broker:deny"})
	st.PutFlag(model.Flag{ID: "f1", Rule: hostile, Severity: 3, TS: now, SessionID: "s1", Evidence: []model.EvidenceItem{{Kind: "text", Text: hostile}}})
	st.PutIncident(model.IncidentReport{ID: "i1", Rule: hostile, SessionID: "s1", Timestamp: now, Summary: hostile})
	st.PutGuardDecisionForTest(store.GuardDecision{ID: "g1", SessionID: "s1", RuleID: hostile, Verdict: "deny", Scope: "once", At: now.Format(time.RFC3339Nano)})
	st.PutGuardDecisionForTest(store.GuardDecision{ID: "g2", SessionID: "s1", RuleID: "cloud-creds", Verdict: "allow", Scope: "always", At: now.Add(4 * time.Nanosecond).Format(time.RFC3339Nano)})
	st.PutResourceEpisode(resource.Episode{CapturedAt: now, Severity: "warning", DiagnosisCodes: []string{identifierSecret}, Session: resource.Session{Key: "100:" + strconv.FormatInt(started.UnixNano(), 10), RootPID: 100, RootStartedAt: started, Workspace: hostile, Kind: "agent"}})
	st.PutResourceEpisode(resource.Episode{CapturedAt: now.Add(time.Nanosecond), Severity: "warning", DiagnosisCodes: []string{"heavy-memory"}, Session: resource.Session{Key: "100:" + strconv.FormatInt(started.UnixNano(), 10), RootPID: 100, RootStartedAt: started, RSSBytes: 4 << 30, Kind: "agent"}})
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.handleSessionSubpath(w, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory", nil))
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var out memoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	decoded := fmt.Sprintf("%+v", out.Rows)
	for _, secret := range []string{hostile, identifierSecret, "secret-guard-broker"} {
		if strings.Contains(decoded, secret) {
			t.Fatalf("raw payload %q leaked in decoded response: %s", secret, decoded)
		}
	}
	for _, label := range []string{"Tool: Shell command", "Model: Claude Sonnet 4.5", "1200 input", "300 output", "Diagnosis: Heavy memory", "4 GiB", "Cloud credentials", "Scope: Always"} {
		if !strings.Contains(decoded, label) {
			t.Fatalf("known label %q missing: %s", label, decoded)
		}
	}
	var direct, resources int
	for _, row := range out.Rows {
		if row.Kind == "guard-audit" {
			direct++
		}
		if row.Kind == "resource" {
			resources++
		}
	}
	if direct != 1 {
		t.Fatalf("direct guard audits=%d, want 1: %s", direct, w.Body.String())
	}
	if resources != 2 {
		t.Fatalf("resource rows=%d, want 2: %s", resources, w.Body.String())
	}
}

func TestSessionMemoryErrors(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.UpsertSession(model.Session{ID: "s1", StartedAt: now, LastSeenAt: now})
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	for _, tc := range []struct {
		path string
		want int
	}{{"/sessions/s1/memory?limit=bad", 400}, {"/sessions/s1/memory?limit=0", 400}, {"/sessions/s1/memory?limit=", 400}, {"/sessions/s1/memory?before=garbage", 400}, {"/sessions/s1/memory?before=", 400}, {"/sessions/missing/memory", 404}} {
		w := httptest.NewRecorder()
		a.handleSessionSubpath(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s: HTTP %d want %d", tc.path, w.Code, tc.want)
		}
	}
}

func TestSessionMemoryPagination(t *testing.T) {
	st := testStore(t)
	now := time.Now().UTC()
	st.UpsertSession(model.Session{ID: "s1", StartedAt: now, LastSeenAt: now})
	for i := 0; i < 3; i++ {
		st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: now.Add(time.Duration(i) * time.Nanosecond), SessionID: "s1"})
	}
	a := newTestAPI("", st, &fakeKiller{}, func() Status { return Status{Running: true} })
	first := httptest.NewRecorder()
	a.handleSessionSubpath(first, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory?limit=2", nil))
	if first.Code != 200 {
		t.Fatalf("first HTTP %d: %s", first.Code, first.Body.String())
	}
	var p1 memoryResponse
	if err := json.Unmarshal(first.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1.Rows) != 2 || !p1.HasEarlier || p1.NextCursor == "" {
		t.Fatalf("first page: %+v", p1)
	}
	second := httptest.NewRecorder()
	a.handleSessionSubpath(second, httptest.NewRequest(http.MethodGet, "/sessions/s1/memory?limit=2&before="+p1.NextCursor, nil))
	if second.Code != 200 {
		t.Fatalf("second HTTP %d: %s", second.Code, second.Body.String())
	}
	var p2 memoryResponse
	if err := json.Unmarshal(second.Body.Bytes(), &p2); err != nil {
		t.Fatal(err)
	}
	if len(p2.Rows) != 1 || p2.HasEarlier || p2.Rows[0].ID == p1.Rows[0].ID || !p2.Rows[0].At.Before(p1.Rows[0].At) {
		t.Fatalf("second page: %+v first: %+v", p2, p1)
	}
}
