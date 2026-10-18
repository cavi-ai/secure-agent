package shellreview

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const routineReply = `{"answers":{"risk":{"type":"choice","choice":"routine","confidence":1,"probabilities":{"routine":1,"review":0,"unknown":0}}}}`
const unknownReply = `{"answers":{"risk":{"type":"choice","choice":"unknown","confidence":1,"probabilities":{"routine":0,"review":0,"unknown":1}}}}`

func TestCheckOnlyAddsDenials(t *testing.T) {
	cases := []struct {
		Name, Reply, Guard, Want, Reason string
		SaveFailure                      bool
	}{
		{"routine", routineReply, "allow", "allow", "", false},
		{"review", reviewReply, "allow", "deny", "model_review", false},
		{"unknown", unknownReply, "allow", "deny", "model_unknown", false},
		{"invalid", "not json", "allow", "deny", "invalid_response", false},
		{"existing-denial", routineReply, "deny", "deny", "existing_denial", false},
		{"storage-failure", routineReply, "allow", "deny", "receipt_unavailable", true},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(tc.Reply)) }))
			defer server.Close()
			saved := make(chan Result, 1)
			s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL, Mode: "block"}, func(v string) (string, bool) { return v, true }, func(r Result) error {
				saved <- r
				if tc.SaveFailure {
					return errors.New("storage unavailable")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			req := Request{Command: "echo hello", Cwd: "/workspace", GuardVerdict: tc.Guard}
			decision, err := s.Check(context.Background(), req)
			if err != nil || decision.Verdict != tc.Want || decision.Reason != tc.Reason {
				t.Fatalf("decision=%+v err=%v", decision, err)
			}
			if tc.Guard == "deny" {
				if calls.Load() != 0 {
					t.Fatal("hard denial consulted the model")
				}
				return
			}
			if !tc.SaveFailure && (decision.ObservationID == "" || decision.RequestDigest == "") {
				t.Fatal("unbound decision")
			}
			result := <-saved
			if result.Mode != "block" || (!tc.SaveFailure && result.ProposedVerdict != tc.Want) {
				t.Fatalf("wrong receipt: %+v", result)
			}
		})
	}
}

func TestCheckRequiresExplicitBlockMode(t *testing.T) {
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: "http://127.0.0.1:1"}, func(v string) (string, bool) { return v, true }, func(Result) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Check(context.Background(), Request{Command: "echo hello", GuardVerdict: "allow"}); err != ErrDisabled {
		t.Fatalf("observe mode checked an action: %v", err)
	}
}

func TestCheckQueueWaitUsesCallerDeadline(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Write([]byte(routineReply))
	}))
	defer server.Close()
	defer close(release)
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL, Mode: "block", TimeoutMS: 5000}, func(v string) (string, bool) { return v, true }, func(Result) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit(Request{Command: "echo first", GuardVerdict: "allow"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	decision, err := s.Check(ctx, Request{Command: "echo queued", GuardVerdict: "allow"})
	if err != nil || decision.Verdict != "deny" || decision.Reason != "deadline" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	// The timed-out caller is still queued behind the blocked observation.
	for i := 0; i < 31; i++ {
		if err := s.Submit(Request{Command: "echo fill", GuardVerdict: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	decision, err = s.Check(context.Background(), Request{Command: "echo full", GuardVerdict: "allow"})
	if err != ErrQueueFull || decision.Verdict != "deny" {
		t.Fatalf("queue pressure permitted an action: %+v %v", decision, err)
	}
}

func TestCheckDoesNotReusePriorDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "rm -rf") {
			w.Write([]byte(reviewReply))
		} else {
			w.Write([]byte(routineReply))
		}
	}))
	defer server.Close()
	s, err := New(context.Background(), Config{Enabled: true, Endpoint: server.URL, Mode: "block"}, func(v string) (string, bool) { return v, true }, func(Result) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.Check(context.Background(), Request{Command: "echo hello", Cwd: "/workspace", GuardVerdict: "allow"})
	if err != nil || first.Verdict != "allow" {
		t.Fatalf("%+v %v", first, err)
	}
	second, err := s.Check(context.Background(), Request{Command: "rm -rf ./important", Cwd: "/workspace", GuardVerdict: "allow"})
	if err != nil || second.Verdict != "deny" || second.RequestDigest == first.RequestDigest || second.ObservationID == first.ObservationID {
		t.Fatalf("%+v %v", second, err)
	}
}
