package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// seedSessions upserts n live sessions; sess-0 is the oldest by last_seen.
func seedSessions(t *testing.T, s *Store, n int) {
	t.Helper()
	base := time.Now().Add(-time.Duration(n) * time.Minute)
	for i := 0; i < n; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		s.UpsertSession(model.Session{ID: fmt.Sprintf("sess-%d", i), Harness: "claude",
			StartedAt: at, LastSeenAt: at, Status: model.SessionActive, Confidence: model.ConfHook})
	}
}

// GetSession is a lookup by id: a session past any list page is still found.
func TestGetSessionBeyondListLimit(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seedSessions(t, s, 1200)
	got, ok := s.GetSession("sess-0")
	if !ok || got.ID != "sess-0" || got.Harness != "claude" {
		t.Fatalf("GetSession(oldest of 1200) = %+v, %v", got, ok)
	}
	if _, ok := s.GetSession("sess-missing"); ok {
		t.Fatal("unknown id must not be found")
	}
}

// TrendFor names the host (CIDR table, no network) and every agent the
// operator already allowed it for.
func TestTrendForCarriesHostIdentity(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetAllowlistSource(func() map[string][]string {
		return map[string][]string{"openclaw": {"160.79.104.10"}, "claude": {"160.79.104.10"}, "codex": {"api.openai.com"}}
	})
	tc := s.TrendFor("", "160.79.104.10")
	if tc.HostOrg != "Anthropic" || !slices.Equal(tc.AllowedFor, []string{"claude", "openclaw"}) {
		t.Fatalf("known host trend = %+v", tc)
	}
	tc = s.TrendFor("", "203.0.113.7")
	if tc.HostOrg != "" || tc.HostName != "" || tc.AllowedFor != nil {
		t.Fatalf("unknown host trend = %+v", tc)
	}
}
