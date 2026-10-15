package hookhealth

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

func TestRepairVerificationUsesNewerScopedEvidence(t *testing.T) {
	base := testRun(0, "error")
	for _, harness := range []string{"claude", "codex", "openclaw", "hermes", "opencode"} {
		for _, tc := range []struct{ status, state string }{
			{"ok", "successful-completion"}, {"inject", "successful-completion"},
			{"error", "still-failing"}, {"cancelled", "unconfirmed"},
			{"block", "decision-observed"}, {"deny", "decision-observed"},
		} {
			t.Run(harness+"/"+tc.status, func(t *testing.T) {
				base.Harness = harness
				next := testRun(1, tc.status)
				next.Harness = harness
				next.Evidence.ReasonCode = "dependency-unavailable"
				v := VerifyRepair([]hookrun.Record{next, base}, "c", "guard.py", base.TS, testNow, false)
				if v.State != tc.state || v.ObservedAt == nil || !v.ObservedAt.Equal(next.TS) || len(v.RunIDs) != 1 || v.RunIDs[0] != next.ID {
					t.Fatalf("newer completion misrepresented: %+v", v)
				}
			})
		}
	}
}

func TestRepairVerificationNeverInfersRecoveryFromMissingOrAmbiguousEvidence(t *testing.T) {
	for _, mode := range []string{"waiting", "baseline-missing", "expired", "truncated", "tied-baseline", "tied-baseline-config", "tied-outcomes", "tied-configurations", "future"} {
		t.Run(mode, func(t *testing.T) {
			base, next := testRun(0, "error"), testRun(1, "ok")
			runs := []hookrun.Record{base, next}
			now, truncated, want := testNow, false, "unconfirmed"
			switch mode {
			case "waiting":
				runs, want = runs[:1], "awaiting-completion"
			case "baseline-missing":
				runs = runs[1:]
			case "expired":
				now = testNow.Add(Window)
			case "truncated":
				truncated = true
			case "tied-baseline", "tied-baseline-config":
				runs[1].TS = base.TS
				if mode == "tied-baseline-config" {
					runs[1].Evidence.ConfigID = "other"
				}
			case "tied-outcomes", "tied-configurations":
				peer := testRun(2, "error")
				peer.TS = next.TS
				if mode == "tied-configurations" {
					peer.Status = "ok"
					peer.Evidence.ConfigID = "other"
				}
				runs = append(runs, peer)
			case "future":
				runs[1].TS = now.Add(time.Minute)
				want = "awaiting-completion"
			}
			if got := VerifyRepair(runs, "c", "guard.py", base.TS, now, truncated); got.State != want {
				t.Fatalf("%s implied recovery: %+v", mode, got)
			}
		})
	}
}

func TestRepairVerificationSeparatesConfigurationChangesAndLatestFailure(t *testing.T) {
	base, good, bad := testRun(0, "error"), testRun(1, "ok"), testRun(2, "error")
	v := VerifyRepair([]hookrun.Record{base, good, bad}, "c", "guard.py", base.TS, testNow, false)
	if v.State != "still-failing" {
		t.Fatalf("earlier success hid newer failure: %+v", v)
	}
	good.Evidence.ConfigID = "new-config"
	good.Script = "replacement.py"
	v = VerifyRepair([]hookrun.Record{base, good}, "c", "guard.py", base.TS, testNow, false)
	if v.State != "configuration-changed" || v.ConfigID != "new-config" {
		t.Fatalf("new configuration repaired old one: %+v", v)
	}
	good.Evidence.ConfigID = ""
	if v := VerifyRepair([]hookrun.Record{base, good}, "c", "guard.py", base.TS, testNow, false); v.State != "unconfirmed" {
		t.Fatalf("missing revision became known: %+v", v)
	}
}
