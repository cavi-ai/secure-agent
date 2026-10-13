package api

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

type memoryWorktreeStore struct {
	memoryAdvisorVerdicts
	asks        []model.AgentAsk
	askErr      error
	sessions    []model.Session
	sessionErr  error
	sessionRead int
	totals      model.CleanupTotals
	totalsErr   error
	totalsAt    time.Time
	entries     []model.CleanupEntry
	entryErr    error
	entryLimit  int
	daily       []model.CleanupDay
	dailyErr    error
	dailyDays   int
}

func (s *memoryWorktreeStore) AgentAsks(int) ([]model.AgentAsk, error) { return s.asks, s.askErr }
func (s *memoryWorktreeStore) ListSessions(f store.SessionFilter) ([]model.Session, error) {
	s.sessionRead++
	if f.Status != model.SessionActive || f.Limit != 10000 {
		return nil, errors.New("askable rows read every active session")
	}
	return s.sessions, s.sessionErr
}
func (s *memoryWorktreeStore) CleanupTotals(at time.Time) (model.CleanupTotals, error) {
	s.totalsAt = at
	return s.totals, s.totalsErr
}
func (s *memoryWorktreeStore) CleanupLog(limit int) ([]model.CleanupEntry, error) {
	s.entryLimit = limit
	return s.entries, s.entryErr
}
func (s *memoryWorktreeStore) CleanupDaily(_ time.Time, days int) ([]model.CleanupDay, error) {
	s.dailyDays = days
	return s.daily, s.dailyErr
}

func worktreeViewReport() worktreehunter.ScanReport {
	return worktreehunter.ScanReport{Repos: []worktreehunter.RepoReport{{Path: "/r", Worktrees: []worktreehunter.Worktree{
		{Path: "/r", Head: "h0", State: worktreehunter.StateMain},
		{Path: "/r/.worktrees/a", Head: "h1", State: worktreehunter.StateKeep, InUse: true},
		{Path: "/r/.worktrees/b", Head: "h2", State: worktreehunter.StateReview, InUse: true, Orphan: true},
	}}}}
}

func TestWorktreeReportEnrichmentFromOneStore(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := &memoryWorktreeStore{
		memoryAdvisorVerdicts: memoryAdvisorVerdicts{verdicts: map[string]model.AdvisorVerdict{"worktree:/r/.worktrees/a@h1": {Assessment: "keep"}}},
		asks:                  []model.AgentAsk{{ID: 2, Path: "/r/.worktrees/a", Status: "done"}, {ID: 1, Path: "/r/.worktrees/a", Status: "running"}},
		sessions:              []model.Session{{Harness: "codex", Status: model.SessionActive, Confidence: model.ConfHook, Workspace: "/r/.worktrees/a/sub"}, {Harness: "claude", Status: model.SessionActive, Confidence: model.ConfHook, Workspace: "/r/.worktrees/b"}},
		totals:                model.CleanupTotals{Bytes: 42, Count: 3},
	}
	src := worktreeViewReport()
	rep := enrichWorktreeReport(st, src, true, now)
	if st.kind != "worktree" || !reflect.DeepEqual(st.ids, []string{"worktree:/r/.worktrees/a@h1", "worktree:/r/.worktrees/b@h2"}) {
		t.Fatalf("notes asked about %v (%s)", st.ids, st.kind)
	}
	if !reflect.DeepEqual(rep.Advice, map[string]model.AdvisorVerdict{"/r/.worktrees/a": {Assessment: "keep"}}) {
		t.Fatalf("advice = %+v", rep.Advice)
	}
	if len(rep.Asks) != 1 || rep.Asks["/r/.worktrees/a"].ID != 2 {
		t.Fatalf("asks = %+v, want the newest ask per path", rep.Asks)
	}
	if !reflect.DeepEqual(rep.Askable, map[string]string{"/r/.worktrees/a": "codex"}) {
		t.Fatalf("askable = %+v, want only the in-use keep row with a live session", rep.Askable)
	}
	if rep.Reclaimed == nil || *rep.Reclaimed != st.totals || !st.totalsAt.Equal(now) {
		t.Fatalf("reclaimed = %+v at %v", rep.Reclaimed, st.totalsAt)
	}
	if !reflect.DeepEqual(src, worktreeViewReport()) {
		t.Fatal("enrichment modified the scanned report")
	}
}

func TestWorktreeReportWithoutAskerOrSessions(t *testing.T) {
	st := &memoryWorktreeStore{sessions: []model.Session{{Harness: "codex", Status: model.SessionActive, Confidence: model.ConfHook, Workspace: "/r/.worktrees/a"}}}
	rep := enrichWorktreeReport(st, worktreeViewReport(), false, time.Now())
	if rep.Askable != nil || st.sessionRead != 0 {
		t.Fatalf("asker off: askable = %+v after %d session reads", rep.Askable, st.sessionRead)
	}
	if rep.Advice != nil || rep.Asks != nil || rep.Reclaimed == nil {
		t.Fatalf("empty store: advice %+v, asks %+v, reclaimed %v", rep.Advice, rep.Asks, rep.Reclaimed)
	}
	st.sessionErr = errors.New("sessions unavailable")
	if rep := enrichWorktreeReport(st, worktreeViewReport(), true, time.Now()); rep.Askable != nil {
		t.Fatalf("failed session read offered rows: %+v", rep.Askable)
	}
}

func TestWorktreeReportLeavesOutUnreadableEnrichment(t *testing.T) {
	failed := errors.New("ledger unavailable")
	st := &memoryWorktreeStore{
		asks:   []model.AgentAsk{{ID: 1, Path: "/r/.worktrees/a"}},
		askErr: failed, totals: model.CleanupTotals{Bytes: 42}, totalsErr: failed,
	}
	rep := enrichWorktreeReport(st, worktreeViewReport(), false, time.Now())
	if rep.Reclaimed != nil || rep.Asks != nil {
		t.Fatalf("failed reads shown as values: reclaimed %+v, asks %+v", rep.Reclaimed, rep.Asks)
	}
	st.askErr, st.totalsErr = nil, nil
	if rep := enrichWorktreeReport(st, worktreeViewReport(), false, time.Now()); rep.Reclaimed == nil || rep.Reclaimed.Bytes != 42 || len(rep.Asks) != 1 {
		t.Fatalf("recovered reads not shown: reclaimed %+v, asks %+v", rep.Reclaimed, rep.Asks)
	}
}

func TestCleanupLedgerDailySeriesOnlyWhenAsked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := &memoryWorktreeStore{totals: model.CleanupTotals{Bytes: 7}, entries: []model.CleanupEntry{{ID: 1}}, daily: []model.CleanupDay{{Day: "2023-11-14"}}}
	got, err := readCleanupLedger(st, now, 25, 0)
	if _, ok := got["daily"]; err != nil || ok || st.dailyDays != 0 || st.entryLimit != 25 || !st.totalsAt.Equal(now) {
		t.Fatalf("ledger without days: %+v, %v (days read %d, limit %d)", got, err, st.dailyDays, st.entryLimit)
	}
	got, err = readCleanupLedger(st, now, 25, 30)
	if err != nil || !reflect.DeepEqual(got, map[string]any{"totals": st.totals, "entries": st.entries, "daily": st.daily}) || st.dailyDays != 30 {
		t.Fatalf("ledger with days: %+v, %v", got, err)
	}
}

func TestCleanupLedgerRejectsAnyFailedRead(t *testing.T) {
	failed := errors.New("ledger unavailable")
	for name, fail := range map[string]func(*memoryWorktreeStore){
		"totals":  func(s *memoryWorktreeStore) { s.totalsErr = failed },
		"entries": func(s *memoryWorktreeStore) { s.entryErr = failed },
		"daily":   func(s *memoryWorktreeStore) { s.dailyErr = failed },
	} {
		st := &memoryWorktreeStore{entries: []model.CleanupEntry{{ID: 1}}, daily: []model.CleanupDay{{Day: "2023-11-14"}}}
		fail(st)
		if got, err := readCleanupLedger(st, time.Now(), 25, 30); !errors.Is(err, failed) || got != nil {
			t.Fatalf("%s failure returned %+v, %v", name, got, err)
		}
	}
}

func TestClutterAdviceBatchKeepsValidPlansOnFailure(t *testing.T) {
	projects := []clutter.ClutterProjectTotal{{Project: "/r/app"}, {Project: "machine"}}
	r := &memoryAdvisorVerdicts{err: errors.New("plans unavailable"), verdicts: map[string]model.AdvisorVerdict{
		"project:machine": {Rationale: "Clear tool caches"},
	}}
	got := clutterAdvice(r, projects)
	if r.reads != 1 || r.kind != "project" || !reflect.DeepEqual(r.ids, []string{"project:/r/app", "project:machine"}) {
		t.Fatalf("plan batch: %+v", r)
	}
	if !reflect.DeepEqual(got, map[string]model.AdvisorVerdict{"machine": {Rationale: "Clear tool caches"}}) {
		t.Fatalf("plans = %+v, want the valid plan keyed by project", got)
	}
	if got := clutterAdvice(&memoryAdvisorVerdicts{}, projects); got != nil {
		t.Fatalf("no plans must leave advice out: %+v", got)
	}
}
