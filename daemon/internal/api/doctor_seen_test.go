package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// POST /doctor/seen clears the bus-drop failure until drops grow again; the
// count stays in status.
func TestDoctorSeenClearsBusDropsUntilTheyGrow(t *testing.T) {
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dropAt := time.Now().Add(-time.Minute)
	a := newTestAPI(Deps{Store: st, Telemetry: TelemetryDeps{
		BusDrops:  func() uint64 { return 3 },
		BusDropAt: func() time.Time { return dropAt },
		LossSeen:  new(collect.LossSeen),
	}})
	if s := a.evidenceStatus(Status{Running: true}); !s.BusDropping {
		t.Fatal("a drop a minute ago is not dropping")
	}

	get := httptest.NewRecorder()
	a.handleDoctorSeen(get, httptest.NewRequest(http.MethodGet, "/doctor/seen", nil))
	if get.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status %d, want 405", get.Code)
	}
	post := httptest.NewRecorder()
	a.handleDoctorSeen(post, httptest.NewRequest(http.MethodPost, "/doctor/seen", nil))
	if post.Code != http.StatusOK {
		t.Fatalf("POST status %d, want 200", post.Code)
	}
	if s := a.evidenceStatus(Status{Running: true}); s.BusDropping || s.BusDrops != 3 {
		t.Fatalf("after seen: dropping %v, drops %d; want false, 3", s.BusDropping, s.BusDrops)
	}

	dropAt = time.Now().Add(time.Second)
	if s := a.evidenceStatus(Status{Running: true}); !s.BusDropping {
		t.Fatal("a drop after the mark is not dropping")
	}
}

func TestDoctorSeenDoesNotAcknowledgeLossAfterDisplayedReport(t *testing.T) {
	displayed := time.Now().Add(-time.Minute)
	dropAt := displayed.Add(time.Second)
	a := newTestAPI(Deps{Telemetry: TelemetryDeps{BusDrops: func() uint64 { return 4 }, BusDropAt: func() time.Time { return dropAt }, LossSeen: new(collect.LossSeen)}})
	w := httptest.NewRecorder()
	a.handleDoctorSeen(w, httptest.NewRequest(http.MethodPost, "/doctor/seen", strings.NewReader(`{"seen_at":"`+displayed.Format(time.RFC3339Nano)+`"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !a.evidenceStatus(Status{}).BusDropping {
		t.Fatal("acknowledgement hid a loss newer than the displayed report")
	}
}

func TestDoctorSeenRejectsInvalidCutoffsWithoutClearingLoss(t *testing.T) {
	for _, body := range []string{`{}`, `{"seen_at":"invalid"}`, `{"seen_at":"2999-01-01T00:00:00Z"}`, `{"seen_at":"2026-01-01T00:00:00Z","unknown":true}`, `{"seen_at":"2026-01-01T00:00:00Z"} {}`} {
		t.Run(body, func(t *testing.T) {
			dropped := time.Now().Add(-time.Second)
			a := newTestAPI(Deps{Telemetry: TelemetryDeps{BusDropAt: func() time.Time { return dropped }, LossSeen: new(collect.LossSeen)}})
			w := httptest.NewRecorder()
			a.handleDoctorSeen(w, httptest.NewRequest(http.MethodPost, "/doctor/seen", strings.NewReader(body)))
			if w.Code != http.StatusBadRequest || !a.evidenceStatus(Status{}).BusDropping {
				t.Fatalf("invalid cutoff status=%d, body=%s", w.Code, w.Body.String())
			}
		})
	}
}
