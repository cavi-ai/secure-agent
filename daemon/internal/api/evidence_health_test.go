package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/resource"
)

func TestTranscriptCheckpointFailureVisibleThroughRecovery(t *testing.T) {
	for _, phase := range []string{"write", "rename"} {
		t.Run(phase, func(t *testing.T) {
			st := testStore(t)
			defer st.Close()
			a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
			dir := t.TempDir()
			source := filepath.Join(dir, "activity.jsonl")
			state := filepath.Join(dir, "offsets.json")
			if err := os.WriteFile(source, []byte("seed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			blocker := state + ".tmp"
			if phase == "rename" {
				blocker = state
			}
			if err := os.Mkdir(blocker, 0o700); err != nil {
				t.Fatal(err)
			}
			b := bus.New(16)
			defer b.Close()
			for _, recovering := range []bool{false, true} {
				if recovering {
					if err := os.Remove(blocker); err != nil {
						t.Fatal(err)
					}
				}
				ts := collect.NewTranscriptScanner(b, []string{source})
				ts.OffsetStatePath = state
				ts.OnCheckpointWrite = st.NoteTranscriptCheckpointWrite
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_ = ts.Run(ctx) // Shutdown flush attempts the seeded checkpoint.
				w := httptest.NewRecorder()
				a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
				var status Status
				if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || status.StorageHealth == nil || status.StorageHealth.Failures != 1 {
					t.Fatalf("checkpoint failure hidden: %s", w.Body.String())
				}
				active := status.StorageHealth.Active
				if (!recovering && (len(active) != 1 || active[0] != "transcript checkpoints")) || (recovering && len(active) != 0) {
					t.Fatalf("incorrect checkpoint recovery state: %+v", status.StorageHealth)
				}
				if state, _ := checkStorage(a.doctorFacts(time.Now())); state != doctorFail {
					t.Fatal("Doctor hides earlier checkpoint failures")
				}
				p := a.computePosture()
				if p.State != "attention" || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "storage_loss" {
					t.Fatalf("posture hides checkpoint fault: %+v", p)
				}
				if recovering {
					data, err := os.ReadFile(state)
					var checkpoint struct {
						Offsets map[string]int64 `json:"offsets"`
					}
					if err != nil || json.Unmarshal(data, &checkpoint) != nil || checkpoint.Offsets[source] != 5 {
						t.Fatalf("recovered checkpoint not persisted: %s, %v", data, err)
					}
				}
			}
		})
	}
}

func TestResourceEpisodeFailureVisibleThroughRecovery(t *testing.T) {
	st := testStore(t)
	defer st.Close()
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	episode := resource.Episode{CapturedAt: time.Now(), Session: resource.Session{CPUPercent: math.Inf(1)}}
	if err := st.PutResourceEpisode(episode); err == nil {
		t.Fatal("invalid episode unexpectedly persisted")
	}
	for _, recovering := range []bool{false, true} {
		if recovering {
			episode.Session.CPUPercent = 0
			if err := st.PutResourceEpisode(episode); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
		var status Status
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || status.StorageHealth == nil || status.StorageHealth.Failures != 1 {
			t.Fatalf("status hides the resource evidence gap: %s", w.Body.String())
		}
		active := status.StorageHealth.Active
		if (!recovering && (len(active) != 1 || active[0] != "resource episodes")) || (recovering && len(active) != 0) {
			t.Fatalf("status reports incorrect recovery state: %+v", status.StorageHealth)
		}
		p := a.computePosture()
		if p.State != "attention" || p.CoverageCount != 1 || p.CoverageItems[0].Kind != "storage_loss" {
			t.Fatalf("posture hides resource evidence loss: %+v", p)
		}
		if !recovering && !strings.Contains(p.CoverageItems[0].Detail, "resource episodes") {
			t.Fatalf("posture omits the failed operation: %+v", p.CoverageItems)
		}
		if state, _ := checkStorage(a.doctorFacts(time.Now())); state != doctorFail {
			t.Fatal("Doctor hides resource evidence loss")
		}
	}
}

func TestPostureSurfacesBusLoss(t *testing.T) {
	a := newTestAPI("", testStore(t), nil, func() Status { return Status{Running: true} })
	a.busDrops = func() uint64 { return 7 }
	a.busDropAt = func() time.Time { return time.Now().Add(-collect.LossWindow - time.Minute) }
	if p := a.computePosture(); p.State != "all-clear" {
		t.Fatalf("posture after drops stopped = %+v, want all-clear", p)
	}
	a.busDropAt = time.Now
	p := a.computePosture()
	if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 1 {
		t.Fatalf("posture hides lost evidence: %+v", p)
	}
	if p.CoverageItems[0].Kind != "event_loss" || !strings.Contains(p.CoverageItems[0].Detail, "7") {
		t.Fatalf("missing event-loss evidence: %+v", p.CoverageItems)
	}
	if state, _ := checkBus(a.doctorFacts(time.Now())); state != doctorFail {
		t.Fatal("Doctor and posture disagree about bus loss")
	}
}

func TestStorageFailureVisibleInStatusPostureAndDoctor(t *testing.T) {
	st := testStore(t)
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	st.Close()
	st.PutEvent(event.Event{Kind: event.KindPluginAction, TS: time.Now(), Detail: "[REDACTED]"})
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/status", nil))
	var body struct {
		StorageHealth *struct {
			Failures uint64   `json:"failures"`
			Active   []string `json:"active"`
		} `json:"storage_health"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.StorageHealth == nil || body.StorageHealth.Failures != 1 || len(body.StorageHealth.Active) != 1 {
		t.Fatalf("status hides failed evidence write: %s", w.Body.String())
	}
	p := a.computePosture()
	if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 2 {
		t.Fatalf("posture hides storage failure: %+v", p)
	}
	kinds := map[string]bool{}
	for _, item := range p.CoverageItems {
		kinds[item.Kind] = true
	}
	if !kinds["storage_loss"] || !kinds["storage_read_failure"] {
		t.Fatalf("posture must report read and write failures separately: %+v", p)
	}
	report := a.doctorReport(time.Now())
	for _, c := range report.Checks {
		if c.ID == "storage" && c.State == doctorFail {
			return
		}
	}
	t.Fatalf("Doctor hides storage failure: %+v", report)
}
