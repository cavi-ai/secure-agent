package store

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func seedReportStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, sess := range []model.Session{
		{ID: "s1", Harness: "claude", Repo: "A", Branch: "main", StartedAt: now.Add(-time.Hour), LastSeenAt: now},
		{ID: "s2", Harness: "codex", Repo: "B", Branch: "dev", StartedAt: now.Add(-time.Hour), LastSeenAt: now},
		{ID: "s3", Harness: "claude", Repo: "A", Branch: "feature", StartedAt: now.Add(-72 * time.Hour), LastSeenAt: now.Add(-71 * time.Hour)},
		{ID: "s4", Harness: "opencode", Repo: "C", StartedAt: now.Add(-time.Minute), LastSeenAt: now},
	} {
		sess.Status, sess.Confidence = model.SessionActive, model.ConfHook
		s.UpsertSession(sess)
	}
	at := func(sec int) time.Time { return now.Add(-time.Hour + time.Duration(sec)*time.Second) }
	for _, e := range []event.Event{
		// Inserted out of time order: the report reads by timestamp.
		{Kind: event.KindModelCall, TS: at(9), Model: "m2", TokensIn: 50, TokensOut: 5},
		{Kind: event.KindTurn, TS: at(1)},
		{Kind: event.KindToolCall, TS: at(2), ToolName: "Bash", ToolStatus: "ok", DurationMs: 500, CallID: "c1"},
		{Kind: event.KindToolCall, TS: at(3), ToolName: "Bash", ToolStatus: "error", DurationMs: 1500, CallID: "c2"},
		{Kind: event.KindToolCall, TS: at(4), ToolName: "Read", ToolStatus: "ok", DurationMs: 200, CallID: "c3"},
		{Kind: event.KindModelCall, TS: at(5), Model: "m1", TokensIn: 100, TokensOut: 10, CostUSD: 0.25},
		{Kind: event.KindFileOpen, TS: at(6), Path: "/w/p1"},
		{Kind: event.KindFileOpen, TS: at(7), Path: "/w/p1"},
		{Kind: event.KindFileOpen, TS: at(8), Path: "/w/p2"},
		{Kind: event.KindFileWrite, TS: at(10), Path: "/w/p1"},
		{Kind: event.KindConnOpen, TS: at(11), RemoteHost: "h1", RemotePort: 443},
		{Kind: event.KindConnOpen, TS: at(12), RemoteHost: "h1", RemotePort: 443},
		{Kind: event.KindGuardResolved, TS: at(13), Detail: "allow/session"},
		{Kind: event.KindTranscriptHit, TS: at(14), Detail: "claude:fingerprint:fp-1"},
		{Kind: event.KindTurn, TS: at(15)},
	} {
		e.SessionID = "s1"
		s.PutEvent(e)
	}
	for _, e := range []event.Event{
		{Kind: event.KindToolCall, TS: at(2), ToolName: "Write", ToolStatus: "error", CallID: "c1"},
		{Kind: event.KindModelCall, TS: at(3), Model: "m1", TokensIn: 7, CostUSD: 1},
		{Kind: event.KindFileOpen, TS: at(4), Path: "/w/p9"},
		{Kind: event.KindConnOpen, TS: at(5), RemoteHost: "h9"},
		{Kind: event.KindTranscriptHit, TS: at(6), Detail: "codex:typed:rule-9"},
	} {
		e.SessionID = "s2"
		s.PutEvent(e)
	}
	s.PutFlag(model.Flag{ID: "f1", Rule: "secret-in-transcript", Severity: 3, TS: at(14), SessionID: "s1"})
	s.PutFlag(model.Flag{ID: "f2", Rule: "exfil", Severity: 2, TS: at(6), SessionID: "s2"})
	return s
}

func TestSessionReportAggregates(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := seedReportStore(t, now)

	rep, ok := s.SessionReport("s1")
	if !ok {
		t.Fatal("s1 not found")
	}
	if rep.Session.ID != "s1" || rep.Session.Repo != "A" || rep.DurationS != 3600 || rep.Events != 15 {
		t.Fatalf("head = session %+v duration %d events %d", rep.Session, rep.DurationS, rep.Events)
	}
	if rep.Turns != 2 || rep.ToolCalls != 3 || rep.ModelCalls != 2 || rep.TokensIn != 150 || rep.TokensOut != 15 ||
		rep.CostUSD != 0.25 || rep.Unpriced != 1 {
		t.Fatalf("totals = turns %d tools %d models %d tokens %d/%d cost %v unpriced %d",
			rep.Turns, rep.ToolCalls, rep.ModelCalls, rep.TokensIn, rep.TokensOut, rep.CostUSD, rep.Unpriced)
	}
	wantTools := []ReportCount{{Key: "Bash", Count: 2, Errors: 1, DurationMs: 2000}, {Key: "Read", Count: 1, DurationMs: 200}}
	if !reflect.DeepEqual(rep.Tools, wantTools) {
		t.Fatalf("tools = %+v, want %+v", rep.Tools, wantTools)
	}
	wantModels := []ReportModel{
		{Model: "m1", Calls: 1, TokensIn: 100, TokensOut: 10, CostUSD: 0.25},
		{Model: "m2", Calls: 1, TokensIn: 50, TokensOut: 5, Unpriced: 1},
	}
	if !reflect.DeepEqual(rep.Models, wantModels) {
		t.Fatalf("models = %+v, want %+v", rep.Models, wantModels)
	}
	if want := []ReportCount{{Key: "/w/p1", Count: 3}, {Key: "/w/p2", Count: 1}}; !reflect.DeepEqual(rep.Files, want) {
		t.Fatalf("files = %+v, want %+v", rep.Files, want)
	}
	if want := []ReportCount{{Key: "h1", Count: 2}}; !reflect.DeepEqual(rep.Hosts, want) {
		t.Fatalf("hosts = %+v, want %+v", rep.Hosts, want)
	}
	if len(rep.Guard) != 1 || rep.Guard[0].Label != "allow/session" || rep.Guard[0].Kind != "guard-resolved" {
		t.Fatalf("guard = %+v", rep.Guard)
	}
	if len(rep.SecretHits) != 1 || rep.SecretHits[0].Label != "fp-1" || rep.SecretHits[0].Status != "fingerprint" {
		t.Fatalf("secret hits = %+v, want rule fp-1 layer fingerprint", rep.SecretHits)
	}
	if len(rep.Flags) != 1 || rep.Flags[0].ID != "f1" {
		t.Fatalf("flags = %+v, want only f1", rep.Flags)
	}
	if len(rep.Timeline) != 15 {
		t.Fatalf("timeline = %d lines, want 15 (s2 excluded)", len(rep.Timeline))
	}
	if !sort.SliceIsSorted(rep.Timeline, func(i, j int) bool { return rep.Timeline[i].TS < rep.Timeline[j].TS }) {
		t.Fatalf("timeline not oldest-first: %+v", rep.Timeline)
	}
	first, bash := rep.Timeline[0], rep.Timeline[2]
	if first.Kind != "turn" || bash.Kind != "tool-call" || bash.Label != "Bash" || bash.Status != "error" || bash.DurationMs != 1500 {
		t.Fatalf("timeline lines = %+v, %+v", first, bash)
	}
	if last := rep.Timeline[8]; last.Kind != "model-call" || last.Label != "m2" {
		t.Fatalf("timeline[8] = %+v, want the late-inserted m2 call in time order", last)
	}
}

func TestSessionReportEmptyAndUnknown(t *testing.T) {
	s := seedReportStore(t, time.Now())
	rep, ok := s.SessionReport("s4")
	if !ok {
		t.Fatal("s4 not found")
	}
	for name, v := range map[string]any{"tools": rep.Tools, "models": rep.Models, "files": rep.Files, "hosts": rep.Hosts,
		"guard": rep.Guard, "secret_hits": rep.SecretHits, "flags": rep.Flags, "timeline": rep.Timeline} {
		rv := reflect.ValueOf(v)
		if rv.IsNil() || rv.Len() != 0 {
			t.Errorf("%s = %#v, want an empty non-nil slice", name, v)
		}
	}
	if _, ok := s.SessionReport("nope"); ok {
		t.Fatal("unknown id reported ok")
	}
}

// An ended session outside the default view's ended tail still reports.
func TestSessionReportFindsOldEndedSession(t *testing.T) {
	now := time.Now()
	s := seedReportStore(t, now)
	for i := 0; i < defaultEndedTail+5; i++ {
		ended := now.Add(-time.Duration(i) * time.Minute)
		s.UpsertSession(model.Session{ID: "e" + string(rune('a'+i)), Harness: "claude", StartedAt: ended, LastSeenAt: ended,
			EndedAt: &ended, Status: model.SessionEnded})
	}
	old := now.Add(-48 * time.Hour)
	s.UpsertSession(model.Session{ID: "old", Harness: "claude", StartedAt: old, LastSeenAt: old, EndedAt: &old, Status: model.SessionEnded})
	if _, ok := s.SessionReport("old"); !ok {
		t.Fatal("old ended session not found")
	}
}

func TestListSessionsFilters(t *testing.T) {
	now := time.Now()
	s := seedReportStore(t, now)
	ids := func(f SessionFilter) []string {
		var out []string
		for _, sess := range s.ListSessions(f) {
			out = append(out, sess.ID)
		}
		sort.Strings(out)
		return out
	}
	for name, tc := range map[string]struct {
		f    SessionFilter
		want []string
	}{
		"none":           {SessionFilter{}, []string{"s1", "s2", "s3", "s4"}},
		"harness":        {SessionFilter{Harness: "claude"}, []string{"s1", "s3"}},
		"repo":           {SessionFilter{Repo: "A"}, []string{"s1", "s3"}},
		"branch":         {SessionFilter{Branch: "main"}, []string{"s1"}},
		"since":          {SessionFilter{Since: now.Add(-24 * time.Hour)}, []string{"s1", "s2", "s4"}},
		"repo+since":     {SessionFilter{Repo: "A", Since: now.Add(-24 * time.Hour)}, []string{"s1"}},
		"status+harness": {SessionFilter{Status: model.SessionActive, Harness: "codex"}, []string{"s2"}},
		"no match":       {SessionFilter{Harness: "claude", Branch: "dev"}, nil},
	} {
		if got := ids(tc.f); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestQueryFlagsBySession(t *testing.T) {
	s := seedReportStore(t, time.Now())
	got := s.QueryFlags(FlagFilter{SessionID: "s2"})
	if len(got) != 1 || got[0].ID != "f2" {
		t.Fatalf("flags for s2 = %+v, want only f2", got)
	}
	if all := s.QueryFlags(FlagFilter{}); len(all) != 2 {
		t.Fatalf("unfiltered flags = %d, want 2", len(all))
	}
}
