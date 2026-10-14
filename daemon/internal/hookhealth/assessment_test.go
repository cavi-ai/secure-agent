package hookhealth

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func testRun(i int, status string) hookrun.Record {
	return hookrun.Record{ID: string(rune('a' + i)), Harness: "hermes", SessionID: "s", TS: testNow.Add(time.Duration(i-10) * time.Second), Event: "pre_tool_call", Script: "guard.py", Status: status,
		Evidence: &hookrun.Evidence{HandlerID: "h", ConfigID: "c"}}
}

func TestFailureNeedsRepeatedErrorsAndRecovers(t *testing.T) {
	runs := []hookrun.Record{testRun(0, "error"), testRun(1, "error"), testRun(2, "error")}
	a := Assess(runs, testNow, false)
	if len(a.Findings) != 1 || a.Findings[0].Kind != "execution-errors" || !a.Findings[0].NeedsAction || a.Findings[0].Count != 3 || a.Findings[0].NextAction == "" || len(a.Findings[0].Limits) == 0 {
		t.Fatalf("missing actionable bounded evidence: %+v", a)
	}
	id := a.Findings[0].ID
	runs = append(runs, testRun(3, "error"))
	if got := Assess(runs, testNow, false); len(got.Findings) != 1 || got.Findings[0].ID != id {
		t.Fatalf("repetition created a new finding: %+v", got)
	}
	for _, status := range []string{"ok", "inject", "block", "deny", "cancelled"} {
		got := Assess(append(runs, testRun(4, status)), testNow, false)
		if len(got.Findings) != 0 {
			t.Errorf("%s did not end consecutive error finding: %+v", status, got)
		}
	}
}

func TestNoInventedAttributionOrStaleEvidence(t *testing.T) {
	for _, mode := range []string{"unattributed", "old", "future", "different-handlers", "different-configs", "cancelled", "success-same-time"} {
		runs := []hookrun.Record{testRun(0, "error"), testRun(1, "error"), testRun(2, "error")}
		for i := range runs {
			switch mode {
			case "unattributed":
				runs[i].Evidence = nil
			case "old":
				runs[i].TS = testNow.Add(-time.Hour)
			case "future":
				runs[i].TS = testNow.Add(time.Hour)
			case "different-handlers":
				runs[i].Evidence.HandlerID = runs[i].ID
			case "different-configs":
				runs[i].Evidence.ConfigID = runs[i].ID
			case "cancelled":
				runs[i].Status = "cancelled"
			}
		}
		if mode == "success-same-time" {
			r := testRun(3, "ok")
			r.TS = runs[2].TS
			runs = append(runs, r)
		}
		got := Assess(runs, testNow, false)
		if len(got.Findings) != 0 {
			t.Errorf("%s produced diagnosis: %+v", mode, got)
		}
	}
}

func TestNewConfigurationSupersedesOldRepairFinding(t *testing.T) {
	runs := []hookrun.Record{testRun(0, "error"), testRun(1, "error"), testRun(2, "error")}
	r := testRun(3, "ok")
	r.Evidence.ConfigID = "new"
	runs = append(runs, r)
	if got := Assess(runs, testNow, false); len(got.Findings) != 0 {
		t.Fatalf("obsolete configuration still needs repair: %+v", got)
	}
}

func TestBlocksRequireSameOperationAndStayAdvisory(t *testing.T) {
	runs := []hookrun.Record{testRun(0, "block"), testRun(1, "deny"), testRun(2, "block")}
	if got := Assess(runs, testNow, false); len(got.Findings) != 0 {
		t.Fatal("inferred a stalled action without correlation")
	}
	for i := range runs {
		runs[i].Evidence.OperationID = "op"
	}
	a := Assess(runs, testNow, false)
	if len(a.Findings) != 1 || a.Findings[0].Kind != "repeated-blocks" || a.Findings[0].NeedsAction {
		t.Fatalf("blocks mislabeled: %+v", a)
	}
	r := testRun(3, "ok")
	r.Evidence.OperationID = "op"
	if got := Assess(append(runs, r), testNow, false); len(got.Findings) != 0 {
		t.Fatalf("old block survived subsequent success: %+v", got)
	}
}

func TestMeasuredAdvisoriesRequireKnownForegroundAndContext(t *testing.T) {
	runs := []hookrun.Record{testRun(0, "inject"), testRun(1, "inject"), testRun(2, "inject")}
	for i := range runs {
		runs[i].DurationMs = 2500
		runs[i].Chars = 15000
	}
	if a := Assess(runs, testNow, false); len(a.Findings) != 0 {
		t.Fatal("guessed metric semantics")
	}
	for i := range runs {
		n := int64(15000)
		runs[i].Evidence.DurationKnown = true
		runs[i].Evidence.ExecutionMode = "foreground"
		runs[i].Evidence.ContextChars = &n
	}
	a := Assess(runs, testNow, false)
	if len(a.Findings) != 2 {
		t.Fatalf("missing measured advisories: %+v", a)
	}
	for _, f := range a.Findings {
		if f.NeedsAction || f.NextAction == "" {
			t.Fatalf("advisory escalated or unactionable: %+v", f)
		}
	}
}

func TestAdvisoriesDoNotOrderTiedRecoveryByOpaqueID(t *testing.T) {
	for _, mode := range []string{"fast", "small-context", "unknown", "background", "error-before-blocks"} {
		runs := []hookrun.Record{testRun(0, "ok"), testRun(1, "ok"), testRun(2, "ok"), testRun(3, "ok")}
		for i := range runs {
			n := int64(15000)
			runs[i].TS = testNow
			runs[i].DurationMs = 2500
			runs[i].Evidence.DurationKnown = true
			runs[i].Evidence.ExecutionMode = "foreground"
			runs[i].Evidence.ContextChars = &n
		}
		kind := "slow-foreground"
		switch mode {
		case "fast":
			runs[0].DurationMs = 1
		case "small-context":
			n := int64(0)
			runs[0].Evidence.ContextChars = &n
			kind = "large-context"
		case "unknown":
			runs[0].Evidence.DurationKnown = false
		case "background":
			runs[0].Evidence.ExecutionMode = "background"
		case "error-before-blocks":
			kind = "repeated-blocks"
			for i := range runs {
				runs[i].Status = "block"
				runs[i].Evidence.OperationID = "op"
			}
			runs[0].Status = "error"
		}
		for _, f := range Assess(runs, testNow, false).Findings {
			if f.Kind == kind {
				t.Errorf("%s ordered tied recovery by id: %+v", mode, f)
			}
		}
	}
}
