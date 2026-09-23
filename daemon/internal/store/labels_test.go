package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func labelStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func lbl(rule, agent, pattern, label, source string) model.OperatorLabel {
	return model.OperatorLabel{Kind: "flag", Rule: rule, Agent: agent, Pattern: pattern, Label: label, Source: source, CreatedAt: time.Now()}
}

// Similar labels rank the exact case first, then the same agent and
// pattern, the same rule and agent, the same pattern, the same rule.
func TestSimilarLabelsRanking(t *testing.T) {
	s := labelStore(t)
	s.PutOperatorLabel(lbl("r2", "", "", "ok", "mark"))              // same rule only
	s.PutOperatorLabel(lbl("", "other", "/w/a", "ok", "allow-path")) // same pattern only
	s.PutOperatorLabel(lbl("r1", "codex", "/w/b", "not_ok", "mark")) // same rule + agent
	s.PutOperatorLabel(lbl("", "codex", "/w/a", "ok", "allow-path")) // same agent + pattern
	s.PutOperatorLabel(lbl("r1", "codex", "/w/a", "ok", "mark"))     // exact
	s.PutOperatorLabel(lbl("zz", "nobody", "/x", "not_ok", "mark"))  // unrelated

	got := s.SimilarLabels("r1", "codex", "/w/a", 10)
	var order []string
	for _, l := range got {
		order = append(order, l.Rule+"|"+l.Agent+"|"+l.Pattern)
	}
	want := []string{"r1|codex|/w/a", "|codex|/w/a", "r1|codex|/w/b", "|other|/w/a"}
	if len(order) != len(want) {
		t.Fatalf("similar = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("similar = %v, want %v", order, want)
		}
	}
	if got := s.SimilarLabels("r1", "codex", "/w/a", 2); len(got) != 2 {
		t.Fatalf("limit: %d", len(got))
	}
	if got := s.SimilarLabels("", "", "", 10); got == nil || len(got) != 0 {
		t.Fatalf("empty keys: %#v, want empty non-nil", got)
	}
}

// A summary counts the same case only: same agent and pattern, or same rule
// and agent when there is no pattern; another agent never counts.
func TestLabelSummaryIsPerCase(t *testing.T) {
	s := labelStore(t)
	s.PutOperatorLabel(lbl("r1", "codex", "/w/a", "ok", "mark"))
	s.PutOperatorLabel(lbl("", "codex", "/w/a", "ok", "allow-path"))
	s.PutOperatorLabel(lbl("r1", "codex", "/w/a", "not_ok", "kill"))
	s.PutOperatorLabel(lbl("r1", "claude", "/w/a", "ok", "mark"))
	s.PutOperatorLabel(lbl("r1", "codex", "", "not_ok", "mark"))

	if got := s.LabelSummary("codex", "/w/a", "r1"); got.OK != 2 || got.NotOK != 1 {
		t.Fatalf("codex /w/a = %+v, want 2 ok 1 not ok", got)
	}
	if got := s.LabelSummary("codex", "", "r1"); got.OK != 0 || got.NotOK != 1 {
		t.Fatalf("codex r1 no pattern = %+v, want 0 ok 1 not ok", got)
	}
	if got := s.LabelSummary("", "", ""); got.OK != 0 || got.NotOK != 0 {
		t.Fatalf("empty = %+v", got)
	}
}
