package advisor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestEgressEpisodePromptRedactedAndInflight(t *testing.T) {
	e := store.EgressEpisode{ID: "0123456789abcdef0123456789abcdef", Scope: store.EgressScope{Agent: "claude", ExePath: "/private/SECRET_EXE", Harness: "claude", Workspace: "/work/SECRET_WORKSPACE"}, Host: "203.0.113.1", Protocol: "tcp", Port: 443, Count: 5, Recurring: true, Intervals: []time.Duration{30 * time.Minute}}
	prompt := egressPrompt(e, true)
	for _, forbidden := range []string{"SECRET_EXE", "SECRET_WORKSPACE", "/private/", "/work/"} {
		if strings.Contains(prompt, forbidden) {
			t.Fatalf("prompt leaked %q: %s", forbidden, prompt)
		}
	}
	if !strings.Contains(prompt, "203.0.113.1") || !strings.Contains(prompt, "30") {
		t.Fatalf("prompt lacks observations: %s", prompt)
	}
	sink := &memSink{rows: map[string]model.AdvisorVerdict{}}
	s := New(Config{Enabled: true, Endpoint: "http://127.0.0.1:1", QueueSize: 1}, sink)
	if !s.EnqueueEgressEpisode(e) || s.EnqueueEgressEpisode(e) {
		t.Fatal("duplicate assessment queued")
	}
	queued := <-s.queue
	s.process(context.Background(), queued)
	if !s.EnqueueEgressEpisode(e) {
		t.Fatal("failed assessment did not clear inflight")
	}
}

func TestEgressEpisodeAssessmentPersistsPurpose(t *testing.T) {
	stub := &chatStub{content: `{"possible_purpose":"Possibly periodic sync","confidence":0.75}`}
	srv := newStubServer(t, stub)
	sink := &memSink{rows: map[string]model.AdvisorVerdict{}}
	s := New(Config{Enabled: true, Endpoint: srv.URL, QueueSize: 2}, sink)
	e := store.EgressEpisode{ID: "0123456789abcdef0123456789abcdef", Scope: store.EgressScope{Agent: "claude", ExePath: "/private/SECRET_EXE", Workspace: "/work/SECRET_WORKSPACE"}, Host: "203.0.113.1", Protocol: "tcp", Port: 443, Count: 5, Recurring: true, Intervals: []time.Duration{30 * time.Minute}}
	if !s.EnqueueEgressEpisode(e) {
		t.Fatal("not queued")
	}
	s.process(context.Background(), <-s.queue)
	v, ok := sink.rows[EgressSubjectID(e.ID)]
	if !ok || v.Assessment != EgressEvidenceKey(e) || v.Rationale != "Possibly periodic sync" || v.Confidence != 0.75 {
		t.Fatalf("verdict=%+v, ok=%t", v, ok)
	}
	for _, secret := range []string{"SECRET_EXE", "SECRET_WORKSPACE"} {
		if strings.Contains(stub.lastBody, secret) {
			t.Fatalf("request leaked %s", secret)
		}
	}
}
