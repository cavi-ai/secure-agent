package store

import (
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionReportIntegerOverflowRejectsPartialTotals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []event.Event
	}{
		{"input total", []event.Event{{Kind: event.KindModelCall, TokensIn: math.MaxInt64}, {Kind: event.KindModelCall, TokensIn: 1}}},
		{"output total", []event.Event{{Kind: event.KindModelCall, TokensOut: math.MaxInt64}, {Kind: event.KindModelCall, TokensOut: 1}}},
		{"model input", []event.Event{{Kind: event.KindModelCall, Model: "a", TokensIn: math.MaxInt64}, {Kind: event.KindModelCall, Model: "b", TokensIn: -math.MaxInt64}, {Kind: event.KindModelCall, Model: "a", TokensIn: 1}}},
		{"model output", []event.Event{{Kind: event.KindModelCall, Model: "a", TokensOut: math.MaxInt64}, {Kind: event.KindModelCall, Model: "b", TokensOut: -math.MaxInt64}, {Kind: event.KindModelCall, Model: "a", TokensOut: 1}}},
		{"tool duration", []event.Event{{Kind: event.KindToolCall, ToolName: "Bash", DurationMs: math.MaxInt64}, {Kind: event.KindToolCall, ToolName: "Bash", DurationMs: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			now := time.Now().UTC()
			if err := s.UpsertSession(model.Session{ID: "s1", Harness: "codex", StartedAt: now, LastSeenAt: now, Status: model.SessionActive}); err != nil {
				t.Fatal(err)
			}
			for i, e := range tc.events {
				e.TS, e.SessionID = now.Add(time.Duration(i)*time.Second), "s1"
				if _, err := s.PutEvent(e); err != nil {
					t.Fatal(err)
				}
			}
			rep, found, err := s.SessionReportResult("s1")
			if err == nil || found || !reflect.DeepEqual(rep, SessionReport{}) {
				t.Errorf("overflow report: %+v, %v, %v", rep, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"session reports"}) || h.Failures != 0 {
				t.Errorf("overflow health: %+v", h)
			}
			if _, err := s.db.Exec(`UPDATE events SET tokens_in=1, tokens_out=1, duration_ms=1`); err != nil {
				t.Fatal(err)
			}
			if rep, found, err := s.SessionReportResult("s1"); err != nil || !found || rep.Events != len(tc.events) {
				t.Fatalf("recovered report: %+v, %v, %v", rep, found, err)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("recovered health: %+v", h)
			}
		})
	}
}

func TestReportIntegerAdditionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		start, value, want int64
		ok                 bool
	}{
		{math.MaxInt64 - 1, 1, math.MaxInt64, true},
		{math.MinInt64 + 1, -1, math.MinInt64, true},
		{math.MaxInt64, 1, math.MaxInt64, false},
		{math.MinInt64, -1, math.MinInt64, false},
		{math.MaxInt64, math.MinInt64, -1, true},
		{math.MinInt64, math.MaxInt64, -1, true},
		{0, math.MaxInt64, math.MaxInt64, true},
		{0, math.MinInt64, math.MinInt64, true},
		{math.MaxInt64, 0, math.MaxInt64, true},
	} {
		got := tc.start
		if ok := addReportInt64(&got, tc.value); ok != tc.ok || got != tc.want {
			t.Errorf("%d + %d: %d, %v; want %d, %v", tc.start, tc.value, got, ok, tc.want, tc.ok)
		}
	}
}
