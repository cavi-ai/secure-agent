package store

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestEventTimeFiltersPreserveNanosecondBounds(t *testing.T) {
	for _, cutoff := range []string{
		"2026-10-11T12:00:00.123456789Z",
		"2026-10-11T13:00:00.123456789+01:00",
		"2026-10-11T12:00:00Z",
		"2026-10-11T12:00:00.999999999Z",
		"2026-10-11T12:00:01Z",
	} {
		t.Run(cutoff, func(t *testing.T) {
			s, err := Open("", "")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			at, err := time.Parse(time.RFC3339Nano, cutoff)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct {
				label string
				ts    time.Time
			}{
				{"before", at.Add(-time.Nanosecond)}, {"at", at}, {"after", at.Add(time.Nanosecond)},
			} {
				if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: row.ts, Detail: row.label, PID: 7, SessionID: "owned", RemoteHost: "api.example.com"}); err != nil {
					t.Fatal(err)
				}
				stamp := row.ts.In(time.FixedZone("west", -4*60*60)).Format(time.RFC3339Nano)
				if _, err := s.db.Exec("UPDATE events SET ts=? WHERE detail=?", stamp, row.label); err != nil {
					t.Fatal(err)
				}
			}
			for _, tc := range []struct {
				name   string
				filter EventFilter
				want   []string
			}{
				{"since", EventFilter{Since: cutoff}, []string{"after", "at"}},
				{"until", EventFilter{Until: cutoff}, []string{"at", "before"}},
				{"both", EventFilter{Since: cutoff, Until: cutoff}, []string{"at"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					rows, err := s.QueryEvents(tc.filter)
					var labels []string
					for _, row := range rows {
						labels = append(labels, row.Detail)
					}
					if err != nil || !slices.Equal(labels, tc.want) {
						t.Fatalf("events=%v err=%v, want %v", labels, err, tc.want)
					}
					filter := tc.filter
					filter.Limit = 1
					labels = nil
					var beforeID int64
					for {
						page, earlier, err := s.QueryRecordedEvents(filter, beforeID)
						if err != nil {
							t.Fatal(err)
						}
						if len(page) != 1 {
							t.Fatalf("page=%v, want one row", page)
						}
						labels = append(labels, page[0].Event.Detail)
						if !earlier {
							break
						}
						beforeID = page[0].ID
					}
					if !slices.Equal(labels, tc.want) {
						t.Fatalf("recorded events=%v, want %v", labels, tc.want)
					}
				})
			}
			if _, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, TS: at, Detail: "unrelated", SessionID: "other"}); err != nil {
				t.Fatal(err)
			}
			kind := int(event.KindFileOpen)
			filter := EventFilter{Kind: &kind, PID: 7, SessionID: "owned", RemoteHost: "api.example.com", Since: cutoff, Until: cutoff, Limit: 1}
			rows, err := s.QueryEvents(filter)
			if err != nil || len(rows) != 1 || rows[0].Detail != "at" {
				t.Fatalf("combined filters: rows=%v err=%v", rows, err)
			}
			q, args := eventQuery(filter)
			if plan := queryPlan(t, s, q, args...); !strings.Contains(plan, "SEARCH events USING INDEX") || strings.Contains(plan, "TEMP B-TREE") {
				t.Fatalf("combined filter plan: %s", plan)
			}
		})
	}
}
