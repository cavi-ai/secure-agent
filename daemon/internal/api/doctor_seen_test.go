package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestDoctorLossReviewIsIndependentOfDeliveryPressure(t *testing.T) {
	st, err := store.Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	dropAt := now.Add(-time.Second)
	fileAt := dropAt
	a := newTestAPI(Deps{Store: st, Status: func() Status {
		return Status{Running: true, ESService: &collect.ESServiceSnapshot{BytesLost: 100, LostAt: &fileAt, Losing: true}}
	}, Telemetry: TelemetryDeps{BusDrops: func() uint64 { return 4 }, BusDropAt: func() time.Time { return dropAt }, BusDropping: func() bool { return true }, LossSeen: new(collect.LossSeen)}})
	review := func() (bool, string) {
		t.Helper()
		report := a.doctorReport(now)
		generated, err := time.Parse(time.RFC3339Nano, report.GeneratedAt)
		if err != nil || !generated.Equal(now) {
			t.Fatalf("displayed cutoff lost precision: %s", report.GeneratedAt)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			LossReview *struct {
				Pending bool   `json:"pending"`
				SeenAt  string `json:"seen_at"`
			} `json:"loss_review"`
		}
		if err := json.Unmarshal(data, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.LossReview == nil {
			t.Fatal("loss review state missing from Doctor")
		}
		return wire.LossReview.Pending, wire.LossReview.SeenAt
	}
	if pending, _ := review(); !pending {
		t.Fatal("unreviewed loss was hidden")
	}
	w := httptest.NewRecorder()
	a.handleDoctorSeen(w, httptest.NewRequest(http.MethodPost, "/doctor/seen", strings.NewReader(`{"seen_at":"`+now.Format(time.RFC3339Nano)+`"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("acknowledgement: %d %s", w.Code, w.Body.String())
	}
	if pending, seenAt := review(); pending || seenAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("review was not retained: pending=%v seen_at=%q", pending, seenAt)
	}
	if !a.evidenceStatus(Status{}).BusDropping {
		t.Fatal("acknowledgement hid active delivery pressure")
	}
	fileAt = now.Add(time.Nanosecond)
	if pending, _ := review(); !pending {
		t.Fatal("newer file loss was hidden")
	}
	fileAt = now.Add(-time.Second)
	dropAt = now.Add(time.Nanosecond)
	if pending, _ := review(); !pending {
		t.Fatal("newer loss was hidden")
	}
}

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
