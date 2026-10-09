package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/sysagent"
)

type scheduledFlush struct {
	d time.Duration
	f func()
}

// autoReviewRig is an API with a local agent on a stub Ollama and a captured
// flush scheduler. release, when non-nil, holds every model answer until
// closed.
type autoReviewRig struct {
	a        *API
	agent    *sysagent.Agent
	st       *store.Store
	mu       sync.Mutex
	sched    []scheduledFlush
	endpoint string
}

func newAutoReviewRig(t *testing.T, enabled, autoReview bool, release chan struct{}) *autoReviewRig {
	t.Helper()
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			fmt.Fprint(w, `{"models":[{"name":"qwen3:latest"}]}`)
		case "/api/version":
			fmt.Fprint(w, `{"version":"0.15.0"}`)
		default:
			if release != nil {
				<-release
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": "Reviewed."}}}})
		}
	}))
	t.Cleanup(ollama.Close)
	st := testStore(t)
	agent := sysagent.New(st, t.TempDir(), func(s string) (string, bool) { return s, true })
	agent.SetConfig(config.SystemAgentConfig{Enabled: enabled, Endpoint: ollama.URL, TimeoutMinutes: 1, AutoReview: autoReview})
	rig := &autoReviewRig{a: New(Deps{Store: st, SysAgent: agent}), agent: agent, st: st, endpoint: ollama.URL}
	at := time.Now()
	rig.a.autoReview.now = func() time.Time { return at }
	rig.a.autoReview.schedule = func(d time.Duration, f func()) {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		rig.sched = append(rig.sched, scheduledFlush{d, f})
	}
	return rig
}

func (r *autoReviewRig) flag(id string, sev int, acked bool) model.Flag {
	fl := model.Flag{ID: id, Rule: "secret-in-transcript", Agent: "claude", Severity: sev, TS: time.Now(), Acknowledged: acked}
	r.st.PutFlag(fl)
	return fl
}

func (r *autoReviewRig) scheduled() []scheduledFlush {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]scheduledFlush(nil), r.sched...)
}

// reviews returns the automatic review requests, oldest first.
func (r *autoReviewRig) reviews() []model.SysAgentMessage {
	var out []model.SysAgentMessage
	for _, m := range r.agent.Messages(100) {
		if m.Role == "user" && strings.HasPrefix(m.Content, "Automatic review of new findings.") {
			out = append(out, m)
		}
	}
	return out
}

// New findings of severity 2+ gather into one review after the delay; a
// repeat, a severity-1 finding and an acknowledged one are left out.
func TestAutoReviewBatchesNewFindings(t *testing.T) {
	r := newAutoReviewRig(t, true, true, nil)
	f1, f2 := r.flag("f1", 2, false), r.flag("f2", 3, false)
	for _, fl := range []model.Flag{f1, f1, f2, r.flag("f3", 1, false), r.flag("f4", 2, true)} {
		r.a.NoteNewFlag(fl)
	}
	s := r.scheduled()
	if len(s) != 1 || s[0].d != autoReviewDelay {
		t.Fatalf("scheduled = %+v, want one flush after %s", s, autoReviewDelay)
	}
	s[0].f()
	r.agent.Wait()
	got := r.reviews()
	if len(got) != 1 || strings.Join(got[0].FlagIDs, ",") != "f1,f2" {
		t.Fatalf("reviews = %+v, want one carrying f1,f2", got)
	}
	for _, out := range []string{"id=f3", "id=f4"} {
		if strings.Contains(got[0].Content, out) {
			t.Fatalf("review carries %s", out)
		}
	}
	if len(r.scheduled()) != 1 {
		t.Fatal("nothing pending, yet another flush was scheduled")
	}
}

// Without auto_review, or with the agent off, nothing is queued.
func TestAutoReviewOffQueuesNothing(t *testing.T) {
	for _, tc := range []struct{ enabled, auto bool }{{true, false}, {false, true}} {
		r := newAutoReviewRig(t, tc.enabled, tc.auto, nil)
		r.a.NoteNewFlag(r.flag("f1", 3, false))
		if s := r.scheduled(); len(s) != 0 {
			t.Fatalf("enabled=%v auto_review=%v: scheduled %d flushes", tc.enabled, tc.auto, len(s))
		}
	}
}

// A review carries at most autoReviewBatch findings; the rest wait out the
// gap; a finding acknowledged while it waited is not reviewed.
func TestAutoReviewCapsBatchAndSpacesReviews(t *testing.T) {
	r := newAutoReviewRig(t, true, true, nil)
	for i := 0; i < autoReviewBatch+2; i++ {
		r.a.NoteNewFlag(r.flag(fmt.Sprintf("f%02d", i), 2, false))
	}
	r.scheduled()[0].f()
	r.agent.Wait()
	s := r.scheduled()
	if len(s) != 2 || s[1].d != autoReviewGap {
		t.Fatalf("scheduled = %+v, want the rest after %s", s, autoReviewGap)
	}
	r.st.AcknowledgeFlags([]string{fmt.Sprintf("f%02d", autoReviewBatch)})
	s[1].f()
	r.agent.Wait()
	got := r.reviews()
	if len(got) != 2 || len(got[0].FlagIDs) != autoReviewBatch || strings.Join(got[1].FlagIDs, ",") != fmt.Sprintf("f%02d", autoReviewBatch+1) {
		t.Fatalf("reviews carry %v", func() (ids [][]string) {
			for _, m := range got {
				ids = append(ids, m.FlagIDs)
			}
			return
		}())
	}
}

// A busy agent (still answering) keeps the batch and retries after the gap.
func TestAutoReviewKeepsTheBatchWhileTheAgentIsBusy(t *testing.T) {
	release := make(chan struct{})
	r := newAutoReviewRig(t, true, true, release)
	r.a.NoteNewFlag(r.flag("f1", 2, false))
	r.scheduled()[0].f()
	r.a.NoteNewFlag(r.flag("f2", 2, false))
	s := r.scheduled()
	if len(s) != 2 || s[1].d != autoReviewGap {
		t.Fatalf("scheduled = %+v, want f2 after the gap", s)
	}
	s[1].f() // the agent is still answering f1
	s = r.scheduled()
	if len(s) != 3 || s[2].d != autoReviewGap {
		t.Fatalf("busy flush must retry after the gap: %+v", s)
	}
	close(release)
	r.agent.Wait()
	s[2].f()
	r.agent.Wait()
	got := r.reviews()
	if len(got) != 2 || strings.Join(got[1].FlagIDs, ",") != "f2" {
		t.Fatalf("reviews = %d, last carries %v; want f2 reviewed after the retry", len(got), got[len(got)-1].FlagIDs)
	}
}

// Exercise the persisted policy through the actual queue and local review path.
func (r *autoReviewRig) policy(t *testing.T, yaml string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("system_agent:\n  enabled: true\n  auto_review: true\n  endpoint: "+r.endpoint+"\n"+yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadStrict(p)
	if err != nil {
		t.Fatal(err)
	}
	r.agent.SetConfig(cfg.SystemAgent)
}

func TestAutoReviewUsesConfiguredEligibility(t *testing.T) {
	r := newAutoReviewRig(t, true, true, nil)
	r.policy(t, "  auto_review_min_severity: 3\n  auto_review_excluded_rules: [secret-in-transcript]\n")
	excluded := r.flag("excluded", 3, false)
	low := r.flag("low", 2, false)
	low.Rule = "proxy-secret-leak"
	r.st.PutFlag(low)
	included := r.flag("included", 3, false)
	included.Rule = "proxy-secret-leak"
	r.st.PutFlag(included)
	for _, f := range []model.Flag{excluded, low, included} {
		r.a.NoteNewFlag(f)
	}
	r.scheduled()[0].f()
	r.agent.Wait()
	got := r.reviews()
	if len(got) != 1 || strings.Join(got[0].FlagIDs, ",") != "included" {
		t.Fatalf("reviews = %+v, want only included", got)
	}
}

func TestAutoReviewRechecksPolicyBeforeSending(t *testing.T) {
	r := newAutoReviewRig(t, true, true, nil)
	r.a.NoteNewFlag(r.flag("excluded", 3, false))
	r.a.NoteNewFlag(r.flag("low", 2, false))
	keep := r.flag("keep", 3, false)
	keep.Rule = "proxy-secret-leak"
	r.st.PutFlag(keep)
	r.a.NoteNewFlag(keep)
	r.policy(t, "  auto_review_min_severity: 3\n  auto_review_excluded_rules:\n    - secret-in-transcript\n")
	r.scheduled()[0].f()
	r.agent.Wait()
	got := r.reviews()
	if len(got) != 1 || strings.Join(got[0].FlagIDs, ",") != "keep" {
		t.Fatalf("reviews = %+v, want only keep after policy change", got)
	}
}

func TestAutoReviewCanIncludeInformationalFindings(t *testing.T) {
	r := newAutoReviewRig(t, true, true, nil)
	r.policy(t, "  auto_review_min_severity: 1\n")
	r.a.NoteNewFlag(r.flag("info", 1, false))
	if len(r.scheduled()) != 1 {
		t.Fatal("informational finding did not queue")
	}
	r.scheduled()[0].f()
	r.agent.Wait()
	if got := r.reviews(); len(got) != 1 || strings.Join(got[0].FlagIDs, ",") != "info" {
		t.Fatalf("reviews = %+v", got)
	}
}
