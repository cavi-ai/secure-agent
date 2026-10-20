package store

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// readsSkipStoreLock runs each read while the test holds mu and fails, naming
// the reads, if any of them waits for it.
func readsSkipStoreLock(t *testing.T, s *Store, reads map[string]func() error) {
	t.Helper()
	type result struct {
		name string
		err  error
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	done := make(chan result, len(reads))
	for name, read := range reads {
		go func() { done <- result{name, read()} }()
	}
	waiting := maps.Clone(reads)
	deadline := time.After(5 * time.Second)
	for len(waiting) > 0 {
		select {
		case r := <-done:
			delete(waiting, r.name)
			if r.err != nil {
				t.Errorf("%s: %v", r.name, r.err)
			}
		case <-deadline:
			t.Fatalf("reads waited for the store lock: %v", slices.Sorted(maps.Keys(waiting)))
		}
	}
}

func lockTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func want(ok bool, format string, args ...any) error {
	if ok {
		return nil
	}
	return fmt.Errorf(format, args...)
}

// A read transaction never reserves the writer, and its statements keep one
// snapshot while a write commits beside it.
func TestReadTxKeepsOneSnapshotWithoutBlockingWrites(t *testing.T) {
	s := lockTestStore(t)
	count := func(q querier) (n int) {
		t.Helper()
		if err := q.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := s.PutIncident(model.IncidentReport{ID: "i1", FlagID: "f1", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tx, err := s.readTx()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if n := count(tx); n != 1 {
		t.Fatalf("snapshot has %d incidents, want 1", n)
	}
	start := time.Now()
	if err := s.PutIncident(model.IncidentReport{ID: "i2", FlagID: "f2", Timestamp: time.Now()}); err != nil {
		t.Fatalf("write beside a read transaction: %v", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("write waited %v for a read transaction", waited)
	}
	if n := count(tx); n != 1 {
		t.Fatalf("snapshot changed to %d incidents during the transaction", n)
	}
	if n := count(s.db); n != 2 {
		t.Fatalf("store has %d incidents after the write, want 2", n)
	}
}

// Flag and event reads never wait for the store's write lock, so a long
// write or retention statement does not stall the console's reads, and a
// long read does not stall event persistence.
func TestReadsDoNotWaitForTheWriteLock(t *testing.T) {
	s := lockTestStore(t)
	if _, err := s.PutFlag(model.Flag{ID: "f1", Rule: "r", Severity: 2, PID: 1, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdvisorVerdict("f1", "flag", model.AdvisorVerdict{Rationale: "seen", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindExec, PID: 1, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"flags": func() error {
			flags, err := s.QueryFlags(FlagFilter{Limit: 10})
			if err != nil {
				return err
			}
			return want(len(flags) == 1 && flags[0].Advisor != nil, "flags read: %+v", flags)
		},
		"flag with advice": func() error {
			f, ok := s.GetFlagWithAdvisor("f1")
			return want(ok && f.Advisor != nil, "flag with advice: %+v %v", f, ok)
		},
		"verdicts": func() error { _, err := s.AdvisorVerdictsFor([]string{"f1"}, "flag"); return err },
		"events":   func() error { _, err := s.QueryEvents(EventFilter{Limit: 10}); return err },
		"event pages": func() error {
			_, _, err := s.QueryRecordedEvents(EventFilter{Limit: 10}, 0)
			return err
		},
	})
}

// Spend, history, file and audit reports never wait for the store lock.
func TestReportReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	if err := s.UpsertSession(model.Session{ID: "session", Harness: "claude", Confidence: model.ConfHook, StartedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindModelCall, SessionID: "session", Model: "claude-sonnet", TokensIn: 10, TS: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, SessionID: "session", Path: "/work/credentials", PID: 1, TS: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutFlag(model.Flag{ID: "f1", Rule: "r", Agent: "claude", Severity: 2, PID: 1, TS: now,
		Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials"}}}); err != nil {
		t.Fatal(err)
	}
	since, until := now.Add(-time.Hour), now.Add(time.Hour)
	cost := func(by string, opts CostOptions) func() error {
		return func() error {
			rep := s.CostReport(since, until, by, opts)
			return want(rep.Total.Calls == 1 && len(rep.Rows) == 1, "cost by %s: %+v", by, rep)
		}
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"cost by repo":     cost("repo", CostOptions{}),
		"cost by model":    cost("model", CostOptions{}),
		"cost by provider": cost("provider", CostOptions{ProviderFor: func(string) string { return "anthropic" }}),
		"rule counts": func() error {
			last7, _, err := s.RuleCounts("r", "claude", now.Add(time.Minute))
			if err != nil {
				return err
			}
			return want(last7 == 1, "rule counts = %d", last7)
		},
		"path findings": func() error {
			found, err := s.PathFindings("/work/credentials", 10)
			if err != nil {
				return err
			}
			return want(len(found) == 1, "path findings: %+v", found)
		},
		"path accesses": func() error {
			found, err := s.PathAccesses("/work/credentials", 10)
			if err != nil {
				return err
			}
			return want(len(found) == 1, "path accesses: %+v", found)
		},
		"rollups": func() error { s.RollupRange(since); return nil },
		"audit":   func() error { s.RecentAudit(10); return nil },
	})
}

// Hook history, health and evidence reads never wait for the store lock.
func TestHookReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	verify := now.Add(-time.Minute)
	readsSkipStoreLock(t, s, map[string]func() error{
		"hook summaries": func() error { _, err := s.SessionHooks("session"); return err },
		"hook health":    func() error { _, err := s.SessionHookHealth("session", now); return err },
		"hook findings":  func() error { _, _, err := s.ActiveHookFindings(now); return err },
		"hook evidence": func() error {
			_, err := s.SessionHookEvidence("session", HookEvidenceFilter{Harness: "claude", Event: "PreToolUse", EventScope: "exact",
				HandlerID: "handler", Script: "guard.sh", VerifyAfter: &verify}, now)
			return err
		},
	})
}

// Incident reports, links, workflows and details never wait for the store lock.
func TestIncidentReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	if err := s.PutIncident(model.IncidentReport{ID: "i1", FlagID: "f1", Rule: "r", SessionID: "session", Subject: "subject", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"incident": func() error {
			inc, err := s.GetIncident("i1")
			if err != nil {
				return err
			}
			return want(inc.Remediation != nil, "incident: %+v", inc)
		},
		"open incident": func() error { _, _, err := s.FindOpenIncident("r", "session", "subject"); return err },
		"recent incidents": func() error {
			list, err := s.RecentIncidents(10)
			if err != nil {
				return err
			}
			return want(len(list) == 1 && list[0].Remediation != nil, "recent incidents: %+v", list)
		},
		"incident link": func() error {
			id, found, err := s.IncidentIDForFlag("f1")
			if err != nil {
				return err
			}
			return want(found && id == "i1", "incident link = %q %v", id, found)
		},
		"incident links": func() error { _, err := s.IncidentIDsForFlags([]string{"f1", "f2"}); return err },
		"incident status": func() error {
			wf, found, err := s.IncidentStatus("f1")
			if err != nil {
				return err
			}
			return want(found && wf.Status == "open", "incident status: %+v %v", wf, found)
		},
		"incident detail":   func() error { _, err := s.GetIncidentDetail("i1"); return err },
		"incident details":  func() error { _, err := s.RecentIncidentDetails(10); return err },
		"session incidents": func() error { _, err := s.SessionIncidents("session"); return err },
	})
}

// Session lists, lookups and workspace activity never wait for the store lock.
func TestSessionReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	root := now.Add(-time.Hour)
	for _, sess := range []model.Session{
		{ID: "session", Harness: "claude", Workspace: "/work", RootPID: 7, RootStartedAt: root.Format(time.RFC3339Nano), Confidence: model.ConfHook, StartedAt: now, LastSeenAt: now},
		{ID: "ended", Harness: "codex", Confidence: model.ConfHook, StartedAt: now, LastSeenAt: now},
	} {
		if err := s.UpsertSession(sess); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EndSession("ended", now); err != nil {
		t.Fatal(err)
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"sessions": func() error {
			list, err := s.ListSessions(SessionFilter{})
			if err != nil {
				return err
			}
			return want(len(list) == 2 && list[0].ID == "session" && list[1].ID == "ended", "sessions: %+v", list)
		},
		"session": func() error {
			_, found, err := s.GetSession("session")
			if err != nil {
				return err
			}
			return want(found, "session not found")
		},
		"session prefix": func() error { _, err := s.FindSessionsByPrefix("sess"); return err },
		"session roots":  func() error { return want(len(s.SessionRoots()[7]) == 1, "no session root") },
		"root sessions":  func() error { return want(s.SessionsByRootPID()[7].ID == "session", "no root session") },
		"root identity": func() error {
			return want(s.SessionIDForRoot(7, root) == "session", "root identity not found")
		},
		"workspace sessions": func() error { return want(len(s.SessionsInWorkspace("/work")) == 1, "no workspace session") },
		"workspace activity": func() error { return want(len(s.WorkspaceActivity()) == 1, "no workspace activity") },
	})
}

// Operator labels, advisor records, interventions, scan results and resource
// episodes never wait for the store lock.
func TestRecordReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	if _, err := s.PutFlag(model.Flag{ID: "f1", Rule: "r", Agent: "claude", Severity: 3, PID: 1, TS: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOperatorLabel(model.OperatorLabel{Kind: "flag", Rule: "r", Agent: "claude", Pattern: "p", Label: "ok", Source: "operator"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdvisorPlan("f1", model.AdvisorPlan{CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	s.PutScanCache("worktrees", []byte("{}"), now)
	readsSkipStoreLock(t, s, map[string]func() error{
		"similar labels": func() error { _, err := s.SimilarLabels("r", "claude", "p", 10); return err },
		"label summary": func() error {
			sum, err := s.LabelSummary("claude", "p", "r")
			if err != nil {
				return err
			}
			return want(sum.OK == 1, "label summary: %+v", sum)
		},
		"advisor plan": func() error {
			_, found, err := s.AdvisorPlanResultFor("f1")
			if err != nil {
				return err
			}
			return want(found, "advisor plan not found")
		},
		"advisor verdict": func() error { _, _, err := s.AdvisorVerdictResultFor("f1", "flag"); return err },
		"advisor backfill": func() error {
			flags, err := s.CriticalFlagsMissingAdvisor(now.Add(-time.Hour), 10)
			if err != nil {
				return err
			}
			return want(len(flags) == 1, "advisor backfill: %+v", flags)
		},
		"interventions": func() error { _, err := s.RecentInterventions("", 10); return err },
		"scan cache": func() error {
			_, _, ok := s.ScanCache("worktrees")
			return want(ok, "scan cache missing")
		},
		"resource episodes": func() error { s.RecentResourceEpisodes(10); return nil },
	})
}

// Guard allow lists and rules never wait for the store lock.
func TestGuardReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	if err := s.PutGuardPathAllow(GuardPathAllow{Agent: "claude", RuleID: "r", Path: "/work"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGuardRule(GuardRule{Agent: "claude", RuleID: "r", Decision: "allow", Source: "operator"}); err != nil {
		t.Fatal(err)
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"path allowed": func() error { return want(s.GuardPathAllowed("claude", "r", "/work/a"), "path not allowed") },
		"path allows":  func() error { _, err := s.ListGuardPathAllows(10); return err },
		"rule": func() error {
			_, ok := s.LookupGuardRule("claude", "r")
			return want(ok, "guard rule missing")
		},
		"rules": func() error { _, err := s.ListGuardRules(10); return err },
	})
}

// Finding review reads never wait for the store lock.
func TestFindingReviewReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	r, err := s.ObserveFindingReview(f, model.AssessFinding(f))
	if err != nil {
		t.Fatal(err)
	}
	readsSkipStoreLock(t, s, map[string]func() error{
		"review": func() error {
			got, ok, err := s.GetFindingReview(r.ID)
			if err != nil {
				return err
			}
			return want(ok && len(got.SourceIDs) == 1, "review: %+v %v", got, ok)
		},
		"reviews": func() error {
			page, err := s.ListFindingReviews("", 10)
			if err != nil {
				return err
			}
			return want(len(page.Reviews) == 1 && !page.Degraded, "reviews: %+v", page)
		},
		"session reviews": func() error { _, err := s.ListSessionFindingReviews("session"); return err },
		"review link": func() error {
			id, err := s.FindingReviewID("source")
			if err != nil {
				return err
			}
			return want(id == r.ID, "review link = %q", id)
		},
	})
}

// System agent chat, plans and runs never wait for the store lock.
func TestSystemAgentReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now().UTC()
	msg := s.PutSysAgentMessage(model.SysAgentMessage{TS: now, Role: "user"})
	plan := s.PutSysAgentPlan(model.SysAgentPlan{CreatedAt: now})
	s.PutSysAgentRun(model.SysAgentRun{TS: now})
	readsSkipStoreLock(t, s, map[string]func() error{
		"message": func() error {
			_, ok := s.GetSysAgentMessage(msg)
			return want(ok, "message missing")
		},
		"messages":        func() error { return want(len(s.SysAgentMessages(10)) == 1, "no messages") },
		"recommendations": func() error { s.SysAgentRecommendations(10); return nil },
		"pending":         func() error { s.PendingSysAgentRecommendations(); return nil },
		"plan": func() error {
			_, ok := s.GetSysAgentPlan(plan)
			return want(ok, "plan missing")
		},
		"plans": func() error { return want(len(s.SysAgentPlans(10)) == 1, "no plans") },
		"runs":  func() error { return want(len(s.SysAgentRuns(10)) == 1, "no runs") },
	})
}

// Worktree repositories, the cleanup ledger and agent asks never wait for the
// store lock.
func TestWorktreeReadsDoNotWaitForTheStoreLock(t *testing.T) {
	s := lockTestStore(t)
	now := time.Now()
	s.UpsertWorktreeRepo("/work", model.RepoSourceManual, now)
	s.PutCleanup(model.CleanupEntry{TS: now, Action: "remove", Path: "/work/wt", Bytes: 10})
	s.PutAgentAsk(model.AgentAsk{TS: now, Path: "/work/wt", Harness: "claude", SessionID: "session", Status: "done"})
	readsSkipStoreLock(t, s, map[string]func() error{
		"repos": func() error { return want(len(s.WorktreeRepos()) == 1, "no repos") },
		"cleanup log": func() error {
			log, err := s.CleanupLog(10)
			if err != nil {
				return err
			}
			return want(len(log) == 1, "cleanup log: %+v", log)
		},
		"cleanup totals": func() error {
			totals, err := s.CleanupTotals(now)
			if err != nil {
				return err
			}
			return want(totals.Count == 1, "cleanup totals: %+v", totals)
		},
		"cleanup daily": func() error { _, err := s.CleanupDaily(now, 7); return err },
		"asks": func() error {
			asks, err := s.AgentAsks(10)
			if err != nil {
				return err
			}
			return want(len(asks) == 1, "asks: %+v", asks)
		},
	})
}
