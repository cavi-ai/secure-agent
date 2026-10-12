package advisor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestTaskKindNamesArePersistedSet(t *testing.T) {
	var names []string
	for _, k := range []*taskKind{flagKind, incidentKind, hostKind, guardKind, planKind, worktreeKind, projectKind, egressKind} {
		if k.run == nil {
			t.Fatalf("kind %q has no run", k.name)
		}
		names = append(names, k.name)
	}
	slices.Sort(names)
	want := []string{"egress", "flag", "guard", "host", "incident", "plan", "project", "worktree"}
	if !slices.Equal(names, want) {
		t.Fatalf("kind names = %v, want %v", names, want)
	}
}

// Kinds someone asked for run under the on-request timeout; the rest under
// the triage client's.
func TestTaskKindTimeoutClass(t *testing.T) {
	for _, tc := range []struct {
		name string
		task task
		want time.Duration
	}{
		{"flag", task{kind: flagKind, subjectID: "f", flag: model.Flag{ID: "f"}}, time.Second},
		{"plan", task{kind: planKind, subjectID: "incident:i", plan: planReq()}, onRequestTimeout},
		{"worktree", task{kind: worktreeKind, subjectID: "w"}, onRequestTimeout},
		{"project", task{kind: projectKind, subjectID: "p"}, onRequestTimeout},
		{"egress", task{kind: egressKind, subjectID: "e"}, onRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-started:
				default:
					close(started)
				}
				<-release
			}))
			defer srv.Close()
			s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: time.Second}, &memSink{rows: map[string]model.AdvisorVerdict{}})
			done := make(chan struct{})
			go func() {
				s.process(context.Background(), tc.task)
				close(done)
			}()
			<-started
			got := s.Health().TimeoutMS
			close(release)
			<-done
			if got != tc.want.Milliseconds() {
				t.Fatalf("timeout_ms = %d, want %d", got, tc.want.Milliseconds())
			}
		})
	}
}

// A task's in-flight reservation is freed when it ends, even when the model fails.
func TestTaskKindReleasesInflight(t *testing.T) {
	s := New(Config{Enabled: true, Endpoint: "http://127.0.0.1:1", QueueSize: 2}, &memSink{rows: map[string]model.AdvisorVerdict{}})

	e := store.EgressEpisode{ID: "0123456789abcdef0123456789abcdef", Host: "203.0.113.1", Recurring: true}
	if !s.EnqueueEgressEpisode(e) {
		t.Fatal("egress not queued")
	}
	s.process(context.Background(), <-s.queue)
	s.mu.Lock()
	_, pending := s.egressInflight[EgressSubjectID(e.ID)]
	s.mu.Unlock()
	if pending {
		t.Fatal("egress subject still in flight after process")
	}

	req := planReq()
	if !s.EnqueuePlan(req) || !s.PlanPending(req.SubjectID) {
		t.Fatal("plan not pending after enqueue")
	}
	s.process(context.Background(), <-s.queue)
	if s.PlanPending(req.SubjectID) {
		t.Fatal("plan subject still pending after process")
	}
}
