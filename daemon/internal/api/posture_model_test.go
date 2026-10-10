package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestDerivePostureRetainsDecisionsWhenReadsFail(t *testing.T) {
	health := store.WriteHealth{}
	in := postureInputs{
		Status:      Status{Running: true, StorageHealth: &health},
		Generated:   time.Now(),
		FailedReads: []string{"flags", "flags", "finding reviews"},
		Resources:   []resource.Session{mkResourceSession(42, "codex", "/work/repo")},
		Pending:     []guard.Pending{{ID: "prompt", Agent: "codex", Tool: "Read", Path: "/work/repo/.env"}},
	}
	p := derivePosture(in)
	if p.State != "attention" || p.NeedsYou != 1 || len(p.Groups) != 1 || p.Groups[0].RootPID != 42 {
		t.Fatalf("decision lost: %+v", p)
	}
	if p.CoverageCount != 1 || p.CoverageItems[0].Kind != "storage_read_failure" {
		t.Fatalf("read failures hidden: %+v", p)
	}
	if len(health.ReadActive) != 0 {
		t.Fatal("derivation mutated caller's health snapshot")
	}
}

func TestDerivePostureUsesSnapshotTimeForCollectorFreshness(t *testing.T) {
	at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	in := postureInputs{
		Generated: at,
		Status: Status{Running: true, ActiveAgents: 1, Uptime: "1h",
			Collectors: []supervise.Health{{Name: "transcript", Running: true, LastProduced: at.Format(time.RFC3339)}},
		},
	}
	for _, item := range derivePosture(in).CoverageItems {
		if item.Kind == "collector_silent" {
			t.Fatalf("snapshot used wall clock: %+v", item)
		}
	}
	in.Generated = at.Add(24 * time.Hour)
	for _, item := range derivePosture(in).CoverageItems {
		if item.Kind == "collector_silent" {
			return
		}
	}
	t.Fatal("snapshot time advance did not expose stale collector")
}
