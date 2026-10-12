package collect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountPlansNewestSharedQuotaAndIdentityBoundaries(t *testing.T) {
	now := time.Now()
	p := func(home string, pct float64, seen time.Time) PlanSnapshot {
		return PlanSnapshot{Harness: "codex", Home: home, HomePath: home, LimitID: "codex", PlanType: "pro", SeenAt: seen,
			Windows: []PlanWindow{{WindowMinutes: 10080, UsedPercent: pct}}}
	}
	a, b := p("a", 91, now.Add(-time.Hour)), p("b", 47, now)
	other := p("other", 12, now)
	unknown1, unknown2 := p("unknown1", 39, now), p("unknown2", 39, now)
	api := p("api", 80, now)
	changed := p("changed", 90, now)
	changed.AccountKey = "prior-account"
	limit := p("a", 7, now)
	limit.LimitID = "separate-limit"
	out := accountPlans([]PlanSnapshot{a, b, other, unknown1, unknown2, api, changed, limit}, func(home string) (string, bool) {
		switch home {
		case "a", "b":
			return "shared", false
		case "other":
			return "other", false
		case "changed":
			return "new-account", false
		case "api":
			return "", true
		default:
			return "", false
		}
	})
	if len(out) != 5 {
		t.Fatalf("identity groups: %+v", out)
	}
	for _, got := range out {
		if got.AccountKey == "shared" && got.LimitID == "codex" {
			if got.Windows[0].UsedPercent != 47 || got.Home != "shared account" || len(got.Homes) != 2 || !got.SeenAt.Equal(now) {
				t.Fatalf("shared quota must use newest observation, not sum/max: %+v", got)
			}
		}
		if got.Home == "api" || got.Home == "changed" {
			t.Fatalf("obsolete quota: %+v", got)
		}
	}
	// Input remains the per-home persistence source.
	if a.Home != "a" || b.Home != "b" || a.Windows[0].UsedPercent != 91 {
		t.Fatal("mutated source snapshots")
	}
}

func TestCodexPlanIdentityOpaqueAndReflectsLoginChanges(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "auth.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"tokens":{"account_id":"fixture-account"}}`)
	first, api := codexPlanIdentity(home)
	if len(first) != 64 || api || first == "fixture-account" {
		t.Fatalf("identity: %q %v", first, api)
	}
	write(`{"tokens":{"account_id":"different-account"}}`)
	second, _ := codexPlanIdentity(home)
	if first == second {
		t.Fatal("reused an identity after login changed")
	}
	write(`{"auth_mode":"apikey","OPENAI_API_KEY":"fixture-value"}`)
	if key, api := codexPlanIdentity(home); key != "" || !api {
		t.Fatal("API login retained subscription identity")
	}
	write(`{`)
	if key, api := codexPlanIdentity(home); key != "" || api {
		t.Fatal("malformed auth guessed an identity")
	}
}

func TestAccountPlansExcludesRemovedLogins(t *testing.T) {
	current, removed := t.TempDir(), t.TempDir()
	for _, home := range []string{current, removed} {
		if err := os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"tokens":{"account_id":"fixture-account"}}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	account, _ := codexPlanIdentity(current)
	if err := os.Remove(filepath.Join(removed, "auth.json")); err != nil {
		t.Fatal(err)
	}
	older := time.Date(2026, 10, 10, 19, 19, 36, 0, time.UTC)
	newer := time.Date(2026, 10, 12, 21, 20, 46, 0, time.UTC)
	for _, recordedAccount := range []string{"", account} {
		out := accountPlans([]PlanSnapshot{
			{Harness: "codex", Home: "removed", HomePath: removed, PlanType: "pro", LimitID: "codex", SeenAt: older,
				AccountKey: recordedAccount, Windows: []PlanWindow{{WindowMinutes: 10080, UsedPercent: 71}}},
			{Harness: "codex", Home: "current", HomePath: current, PlanType: "pro", LimitID: "codex", SeenAt: newer,
				AccountKey: account, Windows: []PlanWindow{{WindowMinutes: 10080, UsedPercent: 27}}},
		}, codexPlanIdentity)
		if len(out) != 1 || out[0].Home != "current" || out[0].Windows[0].UsedPercent != 27 || !out[0].SeenAt.Equal(newer) {
			t.Fatalf("removed login must not expose a historical quota as current: %+v", out)
		}
	}
}
