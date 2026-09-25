package daemon

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestPlanHeadroomSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	home := filepath.Join(dir, "restart", ".codex")
	old := filepath.Join(dir, "restart-old", ".codex")
	find := func(path string) (collect.PlanSnapshot, bool) {
		i := slices.IndexFunc(collect.Plans(), func(p collect.PlanSnapshot) bool { return p.HomePath == path })
		if i < 0 {
			return collect.PlanSnapshot{}, false
		}
		return collect.Plans()[i], true
	}
	snap := func(used float64, seen time.Time) collect.PlanSnapshot {
		return collect.PlanSnapshot{Harness: "codex", Home: "codex", PlanType: "pro",
			Windows: []collect.PlanWindow{{WindowMinutes: 10080, UsedPercent: used}}, SeenAt: seen}
	}

	// Nothing saved: nothing restored, and an unchanged set is not saved.
	saver := restorePlans(st, now)
	saver.save()
	if _, _, ok := st.ScanCache(planCacheName); ok {
		t.Fatal("saved with no change")
	}

	collect.RecordPlan(home, snap(52, now))
	collect.RecordPlan(old, snap(90, now.Add(-planRestoreMaxAge)))
	saver.save()
	body, _, ok := st.ScanCache(planCacheName)
	if !ok {
		t.Fatal("a new snapshot was not saved")
	}
	var saved []collect.PlanSnapshot
	if err := json.Unmarshal(body, &saved); err != nil || !slices.ContainsFunc(saved, func(p collect.PlanSnapshot) bool { return p.HomePath == home }) {
		t.Fatalf("saved %s (%v)", body, err)
	}

	// The next run: a newer save replaces the row; restore records the
	// snapshots under a week old and never overrides a newer live line.
	collect.RecordPlan(home, snap(60, now.Add(time.Minute)))
	saver.save()
	collect.RecordPlan(home, snap(70, now.Add(2*time.Minute))) // the live line after the restart
	restorePlans(st, now.Add(time.Hour))
	if p, ok := find(home); !ok || p.Windows[0].UsedPercent != 70 {
		t.Fatalf("restored over a newer line: %+v", p)
	}

	// A corrupt row restores nothing and does not fail the start.
	st.PutScanCache(planCacheName, []byte("["), now)
	if s := restorePlans(st, now); s == nil {
		t.Fatal("no saver")
	}
}

func TestRestorePlansSkipsSnapshotsOlderThanAWeek(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	fresh := filepath.Join(dir, "week-fresh", ".codex")
	stale := filepath.Join(dir, "week-stale", ".codex")
	body, _ := json.Marshal([]collect.PlanSnapshot{
		{Harness: "codex", Home: "codex", HomePath: fresh, PlanType: "pro", SeenAt: now.Add(-planRestoreMaxAge + time.Hour)},
		{Harness: "codex", Home: "codex", HomePath: stale, PlanType: "pro", SeenAt: now.Add(-planRestoreMaxAge)},
		{Harness: "codex", Home: "codex", PlanType: "pro", SeenAt: now}, // no home path: never keyed
	})
	st.PutScanCache(planCacheName, body, now)
	saver := restorePlans(st, now)
	has := func(path string) bool {
		return slices.ContainsFunc(collect.Plans(), func(p collect.PlanSnapshot) bool { return p.HomePath == path })
	}
	if !has(fresh) || has(stale) || has("") {
		t.Fatalf("restored %+v", collect.Plans())
	}
	if saver.saved != collect.PlansVersion() {
		t.Fatal("the restored set would be saved back unchanged")
	}
}
