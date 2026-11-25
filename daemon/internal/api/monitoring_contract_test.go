package api

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

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
	if p.State != "all-clear" || p.CoverageCount != 0 || len(p.CoverageItems) != 1 || p.CoverageItems[0].MonitoringState != posture.MonitoringHistorical || b.Dropped() != 1 {
		t.Fatalf("recovery erased history or kept the warning: %+v", p)
	}
	if state, _ := checkBus(a.doctorFacts(time.Now())); state != doctorPass {
		t.Fatal("Doctor disagrees with recovered delivery")
	}
}

func TestRequestedFileTelemetryRequiresACollector(t *testing.T) {
	enabled := true
	st := Status{Running: true, FileTelemetryEnabled: &enabled}
	p := derivePosture(posture.Inputs{Generated: time.Now(), Status: posture.Status(st)})
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
		if p.State != "all-clear" || p.CoverageCount != 0 || len(p.CoverageItems) != 1 || p.CoverageItems[0].MonitoringState != posture.MonitoringDisabled {
			t.Fatalf("bad configuration delta: %+v", p)
		}
	default:
		t.Fatal("unchanged warning counts suppressed a configuration update")
	}
}
