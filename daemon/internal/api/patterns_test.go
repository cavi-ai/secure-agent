package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

const loginKeychain = "/Users/x/Library/Keychains/login.keychain-db"

func keychainFlag(id, agent string, pid int32, ts time.Time, sev int) model.Flag {
	return model.Flag{ID: id, Rule: "keychain-access", Severity: sev, TS: ts, PID: pid, Agent: agent, SessionID: "s1",
		Evidence: []model.EvidenceItem{{Kind: "keychain", Label: loginKeychain, Sub: "keychain access"}}}
}

func onlyPattern(t *testing.T, ps []model.Pattern) model.Pattern {
	t.Helper()
	if len(ps) != 1 {
		t.Fatalf("patterns = %d (%+v), want 1", len(ps), ps)
	}
	return ps[0]
}

func actionByID(acts []model.ExplainAction, id string) *model.ExplainAction {
	if i := actionIndex(acts, id); i >= 0 {
		return &acts[i]
	}
	return nil
}

// A storm of one rule on one subject from two pids is one pattern with its
// cadence and identity.
func TestComputePatternsGroupsBySubject(t *testing.T) {
	a := explainTestAPI(t)
	start := time.Now().Add(-10 * time.Minute)
	for i := 0; i < 330; i++ {
		pid := int32(40844)
		if i >= 320 {
			pid = 51364
		}
		a.store.PutFlag(keychainFlag(fmt.Sprintf("k%03d", i), "codex", pid, start.Add(time.Duration(i)*time.Second), 2))
	}
	p := onlyPattern(t, a.computePatterns(time.Now().Add(-24*time.Hour), 3))
	if p.Count != 330 || p.Unacked != 330 || p.PIDCount != 2 || p.SessionCount != 1 {
		t.Fatalf("count/unacked/pids/sessions = %d/%d/%d/%d, want 330/330/2/1", p.Count, p.Unacked, p.PIDCount, p.SessionCount)
	}
	if p.Bursts < 300 || p.MedianGapS >= 5 {
		t.Fatalf("bursts = %d, median gap = %v; want >= 300 bursts under 5 s", p.Bursts, p.MedianGapS)
	}
	if len(p.PIDs) != 2 || p.PIDs[0] != 40844 {
		t.Fatalf("pids = %v, want the busiest (40844) first", p.PIDs)
	}
	sum := 0
	for _, n := range p.Hourly {
		sum += n
	}
	if sum != 330 || p.Hourly[23] != 330 {
		t.Fatalf("hourly = %v, want 330 in the newest bucket", p.Hourly)
	}
	if p.Key != "codex|keychain-access|"+loginKeychain || p.Subject.Kind != "keychain" || p.Subject.Label != loginKeychain {
		t.Fatalf("key/subject = %q/%+v", p.Key, p.Subject)
	}
	if len(p.FlagIDs) != 330 || p.FlagIDs[0] != "k329" {
		t.Fatalf("flag ids = %d, first %q; want 330, newest first", len(p.FlagIDs), p.FlagIDs[0])
	}
}

// Fewer flags than min are not a pattern; /patterns validates its window.
func TestComputePatternsMinCount(t *testing.T) {
	a := explainTestAPI(t)
	now := time.Now()
	a.store.PutFlag(keychainFlag("a1", "codex", 7, now.Add(-2*time.Minute), 2))
	a.store.PutFlag(keychainFlag("a2", "codex", 7, now.Add(-time.Minute), 2))
	since := now.Add(-time.Hour)
	if ps := a.computePatterns(since, 3); len(ps) != 0 {
		t.Fatalf("min 3 over 2 flags = %+v, want none", ps)
	}
	if p := onlyPattern(t, a.computePatterns(since, 2)); p.Count != 2 {
		t.Fatalf("min 2 count = %d, want 2", p.Count)
	}
	mux := a.buildMux()
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	rec := get("/patterns?min=2")
	var served []model.Pattern
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &served) != nil || len(served) != 1 {
		t.Fatalf("GET /patterns?min=2 = %d %s", rec.Code, rec.Body)
	}
	if rec := get("/patterns"); rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("GET /patterns = %d %q, want []", rec.Code, rec.Body)
	}
	for _, q := range []string{"min=1", "hours=0", "hours=721"} {
		if rec := get("/patterns?" + q); rec.Code != http.StatusBadRequest {
			t.Fatalf("GET /patterns?%s = %d, want 400", q, rec.Code)
		}
	}
}

// The disposition is the worst among OPEN flags: an acknowledged critical
// flag does not count.
func TestPatternDispositionWorstUnacked(t *testing.T) {
	a := explainTestAPI(t)
	now := time.Now()
	a.store.PutFlag(keychainFlag("crit", "codex", 7, now.Add(-3*time.Minute), 3))
	a.store.AcknowledgeFlag("crit")
	a.store.PutFlag(keychainFlag("warn", "codex", 7, now.Add(-2*time.Minute), 2))
	a.store.PutFlag(keychainFlag("benign", "codex", 7, now.Add(-time.Minute), 3))
	a.store.PutAdvisorVerdict("benign", "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.93, Rationale: "Own login.", CreatedAt: now})
	p := onlyPattern(t, a.computePatterns(now.Add(-time.Hour), 3))
	if p.Unacked != 2 || p.Disposition.State != model.DispositionWarning {
		t.Fatalf("unacked/disposition = %d/%+v, want 2/warning", p.Unacked, p.Disposition)
	}
	if p.FlagIDs[len(p.FlagIDs)-1] != "crit" {
		t.Fatalf("flag ids = %v, want the acknowledged one last", p.FlagIDs)
	}
}

func TestPatternAcknowledgedWhenAllAcked(t *testing.T) {
	a := explainTestAPI(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("d%d", i)
		a.store.PutFlag(keychainFlag(id, "codex", 7, now.Add(-time.Duration(i+1)*time.Minute), 3))
		a.store.AcknowledgeFlag(id)
	}
	p := onlyPattern(t, a.computePatterns(now.Add(-time.Hour), 3))
	if p.Unacked != 0 || p.Disposition.State != model.DispositionAcknowledged {
		t.Fatalf("unacked/disposition = %d/%+v, want 0/acknowledged", p.Unacked, p.Disposition)
	}
	if actionByID(p.Actions, "dismiss-all") != nil {
		t.Fatalf("actions = %+v, want no dismiss-all without open flags", p.Actions)
	}
}

// The summary names the agent, the count and the cadence; actions carry the
// served requests, the recommended one following the disposition.
func TestPatternSummaryAndActions(t *testing.T) {
	pinExplainHome(t, "/Users/x")
	a := explainTestAPI(t, AgentSummary{PID: 7, Name: "codex", StartedAt: "2026-09-23T10:00:00Z"})
	now := time.Now()
	for i := 0; i < 4; i++ {
		a.store.PutFlag(keychainFlag(fmt.Sprintf("c%d", i), "codex", 7, now.Add(-time.Duration(4-i)*12*time.Minute), 3))
	}
	for i := 0; i < 3; i++ {
		a.store.PutFlag(model.Flag{ID: fmt.Sprintf("e%d", i), Rule: "proxy-secret-leak", Severity: 3, TS: now.Add(-time.Duration(i+1) * time.Second), PID: 9, Agent: "claude",
			Evidence: []model.EvidenceItem{{Kind: "violation", Label: "proxy-secret-leak:aws-key"}, {Kind: "connect", Label: "api.example.com:443"}}})
		a.store.PutAdvisorVerdict(fmt.Sprintf("e%d", i), "flag", model.AdvisorVerdict{Assessment: "benign", Confidence: 0.9, Rationale: "Test key.", CreatedAt: now})
	}
	ps := a.computePatterns(now.Add(-24*time.Hour), 3)
	if len(ps) != 2 {
		t.Fatalf("patterns = %+v, want 2", ps)
	}
	byRule := map[string]model.Pattern{}
	for _, p := range ps {
		byRule[p.Rule] = p
	}
	kc := byRule["keychain-access"]
	for _, want := range []string{"codex touched the login keychain 4 times", "(1 process, 1 session)", "about every 12 minutes."} {
		if !strings.Contains(kc.Summary, want) {
			t.Fatalf("summary = %q, want %q", kc.Summary, want)
		}
	}
	if strings.Contains(kc.Summary, "c0") || kc.Cadence != "about every 12 minutes" {
		t.Fatalf("summary/cadence = %q/%q", kc.Summary, kc.Cadence)
	}
	mute, dismiss, kill := actionByID(kc.Actions, "mute-class"), actionByID(kc.Actions, "dismiss-all"), actionByID(kc.Actions, "kill")
	if mute == nil || mute.Body["rule"] != "keychain-access" || mute.Body["host"] != "*" {
		t.Fatalf("mute = %+v", mute)
	}
	if dismiss == nil || dismiss.Path != "/flags/acknowledge" || len(dismiss.Body["flag_ids"].([]string)) != 4 {
		t.Fatalf("dismiss-all = %+v", dismiss)
	}
	if kill == nil || !kill.Recommended || kill.Body["pid"] != int32(7) || kill.Body["started_at"] != "2026-09-23T10:00:00Z" {
		t.Fatalf("kill = %+v, want recommended for a critical pattern", kill)
	}

	eg := byRule["proxy-secret-leak"]
	if eg.Subject.Kind != "connect" || eg.Subject.Label != "api.example.com" || eg.Disposition.State != model.DispositionBenignLikely {
		t.Fatalf("egress subject/disposition = %+v/%+v", eg.Subject, eg.Disposition)
	}
	if !strings.Contains(eg.Summary, "claude sent a secret to api.example.com 3 times") || !strings.Contains(eg.Summary, "in bursts a few seconds apart") {
		t.Fatalf("egress summary = %q", eg.Summary)
	}
	allow := actionByID(eg.Actions, "allow-host")
	if allow == nil || !allow.Recommended || allow.Body["host"] != "api.example.com" || allow.Body["agent"] != "claude" {
		t.Fatalf("allow-host = %+v, want recommended for a benign-likely egress pattern", allow)
	}
	if actionByID(eg.Actions, "mute-rule-host") == nil || actionByID(eg.Actions, "kill") != nil {
		t.Fatalf("egress actions = %+v, want mute-rule-host and no kill (pid 9 is not live)", eg.Actions)
	}
}

// POST /flags/acknowledge takes a pattern's {flag_ids} in one call, bounded
// and validated, and still takes {flag_id}.
func TestAcknowledgeFlagIDs(t *testing.T) {
	a := explainTestAPI(t)
	for _, id := range []string{"f1", "f2", "f3", "f4"} {
		a.store.PutFlag(keychainFlag(id, "codex", 7, time.Now(), 2))
	}
	mux := a.buildMux()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/flags/acknowledge", strings.NewReader(body)))
		return rec
	}
	if rec := post(`{"flag_ids":["f1","f2","f3"]}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":3`) {
		t.Fatalf("flag_ids = %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"f1", "f2", "f3"} {
		if f, _ := a.store.GetFlag(id); !f.Acknowledged {
			t.Fatalf("%s not acknowledged", id)
		}
	}
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = fmt.Sprintf("x%d", i)
	}
	big, _ := json.Marshal(map[string]any{"flag_ids": ids})
	for _, body := range []string{string(big), `{"flag_ids":["f4","bad id"]}`, `{}`, `{"flag_ids":[]}`, `{"flag_id":"f4","flag_ids":["f4"]}`} {
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %.40s = %d, want 400", body, rec.Code)
		}
	}
	if f, _ := a.store.GetFlag("f4"); f.Acknowledged {
		t.Fatal("f4 acknowledged by a rejected request")
	}
	if rec := post(`{"flag_id":"f4"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"acknowledged":true`) {
		t.Fatalf("flag_id = %d %s", rec.Code, rec.Body)
	}
}

// Flags a pattern covers are one pattern item in the agent's group and the
// headline; their flag items are gone and groups and items still agree.
func TestAttentionPatternReplacesFlagItems(t *testing.T) {
	a := attentionAPI(t, []resource.Session{mkResourceSession(1, "codex", "/w")})
	now := time.Now()
	covered := map[string]bool{}
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("p%d", i)
		covered[id] = true
		a.store.PutFlag(keychainFlag(id, "codex", 1, now.Add(-time.Duration(i+1)*time.Second), 2))
	}
	a.store.PutFlag(model.Flag{ID: "tcc", Rule: "tcc-tamper", Severity: 3, TS: now, PID: 1, Agent: "codex"})

	p := a.computePosture()
	sum := 0
	var patternItems, flagItems []AttentionItem
	for _, g := range p.Groups {
		sum += len(g.Items)
		for _, it := range g.Items {
			switch it.Kind {
			case "pattern":
				patternItems = append(patternItems, it)
			case "flag":
				flagItems = append(flagItems, it)
			}
		}
	}
	if sum != p.NeedsYou || len(p.Items) != p.NeedsYou || p.NeedsYou != 2 {
		t.Fatalf("group items = %d, items = %d, needs_you = %d; want 2 each\nitems=%+v", sum, len(p.Items), p.NeedsYou, p.Items)
	}
	want := "codex|keychain-access|" + loginKeychain
	if len(patternItems) != 1 || patternItems[0].ID != want || patternItems[0].Count != 4 || patternItems[0].Rule != "keychain-access" ||
		patternItems[0].Disposition == nil || patternItems[0].Disposition.State != model.DispositionWarning || !strings.Contains(patternItems[0].Detail, "4 times") {
		t.Fatalf("pattern items = %+v", patternItems)
	}
	for _, it := range flagItems {
		if covered[it.ID] {
			t.Fatalf("flag item %s is covered by the pattern", it.ID)
		}
	}
	if len(flagItems) != 1 || flagItems[0].ID != "tcc" {
		t.Fatalf("flag items = %+v, want only tcc", flagItems)
	}
	headline := 0
	for _, it := range p.Items {
		if covered[it.ID] {
			t.Fatalf("headline item %+v is covered by the pattern", it)
		}
		if it.Kind == "pattern" && it.ID == want {
			headline++
		}
	}
	if headline != 1 {
		t.Fatalf("headline pattern items = %d, want 1\nitems=%+v", headline, p.Items)
	}
}
