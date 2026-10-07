package store

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func activityStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func activityTime(t *testing.T, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestLastEventTimesUsesChronologicalOrder(t *testing.T) {
	s := activityStore(t)
	for _, value := range []string{
		"2026-10-07T23:00:00Z",
		"2026-10-07T23:00:00.1Z",
		"2026-10-07T23:00:00.01Z",
		"2026-10-08T01:00:00.100000001+02:00",
		"2026-10-07T23:00:00.1Z",
	} {
		s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 7, TS: activityTime(t, value)})
	}
	if got := s.LastEventTimes([]int32{7})[7]; got != "2026-10-07T23:00:00.100000001Z" {
		t.Fatalf("latest activity = %q", got)
	}
}

func TestSessionActivityDoesNotRegress(t *testing.T) {
	for _, operation := range []string{"upsert", "touch", "end"} {
		for _, stored := range []string{"2026-10-07T23:00:00.000000100Z", "2026-10-08T01:00:00.000000100+02:00"} {
			t.Run(operation+stored, func(t *testing.T) {
				s := activityStore(t)
				latest := activityTime(t, stored)
				if err := s.UpsertSession(model.Session{ID: "s", Status: model.SessionIdle, StartedAt: latest.Add(-time.Hour), LastSeenAt: latest}); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at=? WHERE id='s'`, stored); err != nil {
					t.Fatal(err)
				}
				older := latest.Add(-time.Nanosecond)
				var err error
				switch operation {
				case "upsert":
					err = s.UpsertSession(model.Session{ID: "s", Status: model.SessionActive, LastSeenAt: older, Repo: "updated"})
				case "touch":
					err = s.TouchSession("s", older)
				case "end":
					err = s.EndSession("s", older)
				}
				if err != nil {
					t.Fatal(err)
				}
				got, ok := s.GetSession("s")
				wantStatus := model.SessionIdle
				if operation == "end" {
					wantStatus = model.SessionEnded
				}
				if !ok || !got.LastSeenAt.Equal(latest) || got.Status != wantStatus {
					t.Fatalf("stale %s changed activity: %+v", operation, got)
				}
				if operation == "upsert" && got.Repo != "updated" {
					t.Fatal("stale activity discarded identity enrichment")
				}
			})
		}
	}
}

func TestSessionReplayDoesNotReactivateIdle(t *testing.T) {
	for _, operation := range []string{"upsert", "touch"} {
		t.Run(operation, func(t *testing.T) {
			s := activityStore(t)
			now := activityTime(t, "2026-10-07T23:00:00Z")
			if err := s.UpsertSession(model.Session{ID: "s", Status: model.SessionIdle, StartedAt: now, LastSeenAt: now}); err != nil {
				t.Fatal(err)
			}
			var err error
			if operation == "touch" {
				err = s.TouchSession("s", now)
			} else {
				err = s.UpsertSession(model.Session{ID: "s", Status: model.SessionActive, LastSeenAt: now})
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetSession("s"); got.Status != model.SessionIdle {
				t.Fatalf("replay reactivated idle session: %+v", got)
			}
			if err := s.TouchSession("s", now.Add(time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetSession("s"); got.Status != model.SessionActive || !got.LastSeenAt.Equal(now.Add(time.Nanosecond)) {
				t.Fatalf("new activity did not reactivate: %+v", got)
			}
			if err := s.EndSession("s", now.Add(2*time.Nanosecond)); err != nil {
				t.Fatal(err)
			}
			if err := s.TouchSession("s", now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertSession(model.Session{ID: "s", Status: model.SessionActive, LastSeenAt: now}); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetSession("s"); got.Status != model.SessionEnded || !got.LastSeenAt.Equal(now.Add(2*time.Nanosecond)) {
				t.Fatalf("ended activity regressed or reopened: %+v", got)
			}
		})
	}
}

func activitySessions(t *testing.T) *Store {
	t.Helper()
	s := activityStore(t)
	for _, entry := range []struct{ id, at string }{
		{"old", "2026-10-07T23:00:00Z"},
		{"boundary", "2026-10-07T23:00:00.000000001Z"},
		{"new", "2026-10-08T01:00:00.000000002+02:00"},
	} {
		ts := activityTime(t, entry.at)
		if err := s.UpsertSession(model.Session{ID: entry.id, Status: model.SessionActive, StartedAt: ts.Add(-time.Hour), LastSeenAt: ts}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE sessions SET last_seen_at=? WHERE id=?`, entry.at, entry.id); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestSessionsOrderByActivityTime(t *testing.T) {
	s := activitySessions(t)
	for _, status := range []string{"", string(model.SessionActive)} {
		got := s.ListSessions(SessionFilter{Status: status, Limit: 2})
		if len(got) != 2 || got[0].ID != "new" || got[1].ID != "boundary" {
			t.Fatalf("status %q, activity order: %+v", status, got)
		}
	}
}

func TestSessionSinceKeepsNanosecondBoundary(t *testing.T) {
	s := activitySessions(t)
	got := s.ListSessions(SessionFilter{Since: activityTime(t, "2026-10-07T23:00:00.000000002Z")})
	if len(got) != 1 || got[0].ID != "new" {
		t.Fatalf("since boundary includes older activity: %+v", got)
	}
}

func TestSessionIdleCutoffUsesActivityTime(t *testing.T) {
	s := activitySessions(t)
	ids, err := s.MarkSessionsIdle(activityTime(t, "2026-10-07T23:00:00.000000001Z"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"old"}) {
		t.Fatalf("idle IDs = %v, want only old", ids)
	}
	for _, id := range []string{"boundary", "new"} {
		if got, _ := s.GetSession(id); got.Status != model.SessionActive {
			t.Fatalf("fresh session marked idle: %+v", got)
		}
	}
}

func TestSessionEndAdvancesFractionalActivity(t *testing.T) {
	s := activityStore(t)
	now := activityTime(t, "2026-10-07T23:00:00Z")
	if err := s.UpsertSession(model.Session{ID: "s", StartedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	ended := now.Add(time.Nanosecond)
	if err := s.EndSession("s", ended); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSession("s"); !got.LastSeenAt.Equal(ended) || got.EndedAt == nil || !got.EndedAt.Equal(ended) {
		t.Fatalf("ending left stale activity: %+v", got)
	}
}

func TestSessionRetentionUsesChronologicalEndTime(t *testing.T) {
	s := activityStore(t)
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for _, entry := range []struct {
		id string
		at time.Time
	}{
		{"expired", cutoff.Add(-time.Hour).In(time.FixedZone("east", 3*60*60))},
		{"retained", cutoff.Add(time.Hour).In(time.FixedZone("west", -3*60*60))},
	} {
		if err := s.UpsertSession(model.Session{ID: entry.id, StartedAt: entry.at, LastSeenAt: entry.at, Status: model.SessionEnded}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE sessions SET ended_at=? WHERE id=?`, entry.at.Format(time.RFC3339Nano), entry.id); err != nil {
			t.Fatal(err)
		}
	}
	s.pruneSessionsLocked()
	if _, ok := s.GetSession("expired"); ok {
		t.Fatal("expired offset session retained")
	}
	if _, ok := s.GetSession("retained"); !ok {
		t.Fatal("recent offset session pruned")
	}
}
