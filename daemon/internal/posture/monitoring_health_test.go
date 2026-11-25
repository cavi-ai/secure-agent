package posture

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestMonitoringNotesDoNotRequireAttention(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name   string
		status Status
	}{
		{"inspection not selected", Status{Running: true, UninspectedEgress: 3}},
		{"idle collector", Status{Running: true, Uptime: "1h", ActiveAgents: 4,
			Collectors: []supervise.Health{{Name: "transcript", Running: true}},
		}},
		{"ready file collector without activity", Status{Running: true, Uptime: "1h", ActiveAgents: 4,
			Collectors: []supervise.Health{{Name: "eslogger", Running: true}},
			ESService:  &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now().Add(-time.Hour), Collector: &collect.ESCollectorStatus{State: "collecting", UpdatedAt: time.Now()}},
		}},
		{"file telemetry disabled", Status{Running: true, FileTelemetryEnabled: &disabled, ActiveAgents: 1,
			Collectors: []supervise.Health{{Name: "eslogger", Running: false}},
			ESService:  &collect.ESServiceSnapshot{State: "not-loaded", BytesLost: 100, Losing: true},
		}},
		{"guard not configured", Status{Running: true, ActiveAgents: 1, Coverage: &CoverageStatus{
			Harnesses: []HarnessCoverage{{Name: "claude", GuardSupported: true}},
		}}},
		{"recovered storage", Status{Running: true, StorageHealth: &store.WriteHealth{Failures: 3}}},
		{"recovered projection", Status{Running: true, EgressProjectionHealth: &store.EgressProjectionHealth{WriteFailures: 2}}},
		{"past export loss", Status{Running: true, OTLPDropped: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := derive(Inputs{Status: tc.status, Generated: time.Now()})
			if p.State != "all-clear" || p.NeedsYou != 0 || p.CoverageCount != 0 {
				t.Fatalf("a monitoring note became a warning: %+v", p)
			}
			if len(p.CoverageItems) == 0 {
				t.Fatal("monitoring evidence was discarded")
			}
			if p.AttentionSummary.Buckets[2].CoverageCount != 0 {
				t.Fatal("the attention summary disagrees with the headline")
			}
		})
	}
}

func TestMonitoringCurrentFailureStillRequiresAttention(t *testing.T) {
	p := derive(Inputs{Generated: time.Now(), Status: Status{
		Running: true, StorageHealth: &store.WriteHealth{Failures: 3, Active: []string{"events"}},
	}})
	if p.State != "attention" || p.CoverageCount != 1 || p.AttentionSummary.Buckets[2].CoverageCount != 1 {
		t.Fatalf("an active failure was hidden: %+v", p)
	}
}

// A failing root service AND a never-produced tailer are one blind spot:
// posture must carry exactly one collector_silent item for eslogger.
func TestPostureSingleESItemWhenProbeFails(t *testing.T) {
	st := Status{
		Running: true, Uptime: "1h0m0s", ActiveAgents: 2,
		Collectors: []supervise.Health{{Name: "eslogger", Running: true}}, // never produced
		ESService:  &collect.ESServiceSnapshot{State: "spawn scheduled (last exit 1)", SpoolMtime: time.Now().Add(-8 * 24 * time.Hour)},
	}
	count := 0
	for _, it := range SilentCollectorItems(time.Now(), st) {
		if it.ID == "eslogger" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("eslogger items = %d, want exactly 1", count)
	}
	// Healthy probe + silent tailer: the tailer silence still surfaces.
	st.ESService = &collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now()}
	count = 0
	for _, it := range SilentCollectorItems(time.Now(), st) {
		if it.ID == "eslogger" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("healthy probe + silent tailer: eslogger items = %d, want 1 (tailer silence)", count)
	}
}
