package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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
			p := derivePosture(postureInputs{Status: tc.status, Generated: time.Now()})
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

func TestMonitoringBusRecoveryKeepsLossHistory(t *testing.T) {
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	b.Publish(event.Event{})
	b.Publish(event.Event{})
	st := testStore(t)
	defer st.Close()
	a := newTestAPI(Deps{Store: st, Status: func() Status { return Status{Running: true} }, Telemetry: TelemetryDeps{
		BusDrops: b.Dropped, BusDropAt: b.DroppedAt, BusDropping: b.Dropping,
	}})
	if p := a.computePosture(); p.State != "attention" || p.CoverageCount != 1 {
		t.Fatalf("active queue pressure was hidden: %+v", p)
	}
	<-sub
	p := a.computePosture()
	if p.State != "all-clear" || p.CoverageCount != 0 || len(p.CoverageItems) != 1 || p.CoverageItems[0].MonitoringState != monitoringHistorical || b.Dropped() != 1 {
		t.Fatalf("recovery erased history or kept the warning: %+v", p)
	}
	if state, _ := checkBus(a.doctorFacts(time.Now())); state != doctorPass {
		t.Fatal("Doctor disagrees with recovered delivery")
	}
}

func TestMonitoringCurrentFailureStillRequiresAttention(t *testing.T) {
	p := derivePosture(postureInputs{Generated: time.Now(), Status: Status{
		Running: true, StorageHealth: &store.WriteHealth{Failures: 3, Active: []string{"events"}},
	}})
	if p.State != "attention" || p.CoverageCount != 1 || p.AttentionSummary.Buckets[2].CoverageCount != 1 {
		t.Fatalf("an active failure was hidden: %+v", p)
	}
}

func TestRequestedFileTelemetryRequiresACollector(t *testing.T) {
	enabled := true
	st := Status{Running: true, FileTelemetryEnabled: &enabled}
	p := derivePosture(postureInputs{Generated: time.Now(), Status: st})
	if p.State != "attention" || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "collector_down" {
		t.Fatalf("an enabled but unavailable collector was hidden: %+v", p)
	}
	if state, _ := checkFileTelemetry(doctorFacts{st: st}); state != doctorFail {
		t.Fatal("Doctor disagrees with the unavailable collector")
	}
}

func TestMonitoringNoteChangesArePublishedWithoutWarnings(t *testing.T) {
	var choice *bool
	st := testStore(t)
	defer st.Close()
	a := newTestAPI(Deps{Store: st, Status: func() Status { return Status{Running: true, FileTelemetryEnabled: choice} }, Telemetry: TelemetryDeps{DeltaHub: NewDeltaHub()}})
	ch := a.deltaHub.Subscribe()
	defer a.deltaHub.Unsubscribe(ch)
	a.PublishPostureIfChanged()
	<-ch
	disabled := false
	choice = &disabled
	a.PublishPostureIfChanged()
	select {
	case d := <-ch:
		p := d.Data.(Posture)
		if p.State != "all-clear" || p.CoverageCount != 0 || len(p.CoverageItems) != 1 || p.CoverageItems[0].MonitoringState != monitoringDisabled {
			t.Fatalf("bad configuration delta: %+v", p)
		}
	default:
		t.Fatal("unchanged warning counts suppressed a configuration update")
	}
}
