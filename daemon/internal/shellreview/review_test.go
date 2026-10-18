package shellreview

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Kev normalizes confidence relative to uniform probability: p=0.9 with
// three choices has confidence 0.85, not 0.9.
// Protocol: https://github.com/jaredpalmer/kev#api
const reviewReply = `{"answers":{"risk":{"type":"choice","choice":"review","confidence":0.85,"probabilities":{"routine":0.05,"review":0.9,"unknown":0.05}}}}`

func TestReviewMasksInputAndRecordsOnlyMetadata(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ State string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body.State
		w.Write([]byte(reviewReply))
	}))
	defer server.Close()
	records := make(chan Result, 1)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL}, func(v string) (string, bool) {
		return strings.ReplaceAll(v, "private-fixture", "[REDACTED]"), true
	}, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Submit(Request{Command: "curl private-fixture", Cwd: "/workspace", GuardVerdict: "allow"}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-records:
		if got.Choice != "review" || got.Reason != "" || got.Mode != "observe" || got.GuardVerdict != "allow" {
			t.Fatalf("result: %+v", got)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "private-fixture") || strings.Contains(string(b), "curl") {
			t.Fatal("command persisted in result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no observation")
	}
	state := <-received
	if strings.Contains(state, "private-fixture") || !strings.Contains(state, "[REDACTED]") {
		t.Fatal("unmasked classifier input")
	}
	if strings.Contains(state, "guard_verdict") {
		t.Fatal("hook-reported permission was supplied to the classifier")
	}
}

func TestRoundedSystemOneDistributionIsAccepted(t *testing.T) {
	var a answer
	if err := json.Unmarshal([]byte(`{"type":"choice","choice":"review","confidence":0.21,"probabilities":{"routine":0.21,"review":0.47,"unknown":0.31}}`), &a); err != nil {
		t.Fatal(err)
	}
	if !validAnswer(a) {
		t.Fatal("valid independently rounded probabilities rejected")
	}
}

func TestUncertainRoutineAnswerIsAnAbstention(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"answers":{"risk":{"type":"choice","choice":"routine","confidence":0.61,"probabilities":{"routine":0.74,"review":0.2,"unknown":0.06}}}}`))
	}))
	defer server.Close()
	records := make(chan Result, 1)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL}, func(v string) (string, bool) { return v, true }, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Submit(Request{Command: "rm ./example", GuardVerdict: "allow"}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-records:
		if r.Choice != "unknown" || r.Reason != "uncertain_classification" {
			t.Fatalf("uncertainty hidden: %+v", r)
		}
		if r.ModelChoice != "routine" || r.Probabilities["routine"] != 0.74 {
			t.Fatalf("model evidence was lost: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no observation")
	}
	s.Close()
	if h := s.Health(); h.Abstained != 1 || h.Unavailable != 0 {
		t.Fatalf("abstention mislabeled as model failure: %+v", h)
	}
}

func TestUnavailableNeverBecomesRoutine(t *testing.T) {
	for name, reply := range map[string]string{
		"malformed":        "not json",
		"truncated":        `{"truncated":true,"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1,"review":0,"unknown":0}}}}`,
		"missing":          `{"answers":{}}`,
		"null-confidence":  `{"answers":{"risk":{"type":"choice","choice":"routine","confidence":null,"probabilities":{"routine":0.34,"review":0.33,"unknown":0.33}}}}`,
		"null-probability": `{"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1,"review":null,"unknown":0}}}}`,
		"partial":          `{"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1}}}}`,
		"inconsistent":     `{"answers":{"risk":{"type":"choice","choice":"routine","confidence":0.9,"probabilities":{"routine":0.1,"review":0.8,"unknown":0.1}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(reply)) }))
			defer server.Close()
			records := make(chan Result, 1)
			s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL}, func(v string) (string, bool) { return v, true }, func(r Result) error { records <- r; return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Submit(Request{Command: "echo hello", GuardVerdict: "allow"}); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-records:
				if r.Choice != "unknown" || r.Reason != "invalid_response" {
					t.Fatalf("%+v", r)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no observation")
			}
		})
	}
}

func TestQueueDoesNotWaitForClassifier(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	records := make(chan Result, 40)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL, TimeoutMS: 50}, func(v string) (string, bool) { return v, true }, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	req := Request{Command: "echo hello", GuardVerdict: "allow"}
	if err := s.Submit(req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model request did not start")
	}
	for i := 0; i < 32; i++ {
		if err := s.Submit(req); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Submit(req); err != ErrQueueFull {
		t.Fatalf("overflow = %v", err)
	}
	select {
	case r := <-records:
		if r.Choice != "unknown" || r.Reason != "model_unavailable" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("model deadline not enforced")
	}
}

func TestMaskFailureAndOversizedEvidenceAreNotClassified(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(reviewReply)) }))
	defer server.Close()
	records := make(chan Result, 1)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL}, func(v string) (string, bool) { return v, false }, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Submit(Request{Command: strings.Repeat("x", MaxCommandBytes+1), GuardVerdict: "allow"}); err == nil {
		t.Fatal("oversized command accepted")
	}
	if err := s.Submit(Request{Command: "echo hello", GuardVerdict: "deny"}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-records:
		if r.Choice != "unknown" || r.Reason != "redaction_failed" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no observation")
	}
	if calls != 0 {
		t.Fatal("unsafe evidence sent to classifier")
	}
}

func TestRedactedEvidenceCannotBeReportedRoutine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1,"review":0,"unknown":0}}}}`))
	}))
	defer server.Close()
	records := make(chan Result, 1)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL}, func(v string) (string, bool) { return v, true }, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit(Request{Command: "echo [REDACTED]", GuardVerdict: "allow"})
	select {
	case r := <-records:
		if r.Choice != "unknown" || r.Reason != "evidence_redacted" || !r.EvidenceRedacted || r.Confidence != 0 {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no observation")
	}
}

func TestModelRedirectCannotReceiveEvidence(t *testing.T) {
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer source.Close()
	records := make(chan Result, 1)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: source.URL}, func(v string) (string, bool) { return v, true }, func(r Result) error { records <- r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit(Request{Command: "echo hello", GuardVerdict: "allow"})
	select {
	case r := <-records:
		if r.Choice != "unknown" || r.Reason != "model_unavailable" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no observation")
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect received private evidence")
	}
}

func TestDisabledObserverDoesNotAcceptWork(t *testing.T) {
	s, err := New(context.Background(), Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Submit(Request{Command: "echo hello", GuardVerdict: "allow"}) != ErrDisabled || s.Health().Enabled {
		t.Fatal("disabled observer accepted work")
	}
}
