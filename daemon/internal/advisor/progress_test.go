package advisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestHealthReportsActualRequestBudgetAndDeadline(t *testing.T) {
	entered, release, done := make(chan int, 1), make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		entered <- len(body)
		<-release
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"assessment\":\"benign\",\"confidence\":0.5,\"rationale\":\"fixture\"}"}}]}`))
	}))
	defer srv.Close()
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: 120 * time.Second}, &memSink{rows: map[string]model.AdvisorVerdict{}})
	go func() {
		defer close(done)
		s.process(context.Background(), task{kind: "flag", subjectID: "fixture", flag: model.Flag{ID: "fixture"}})
	}()
	bytes := <-entered
	h := s.Health()
	close(release)
	<-done
	encoded, _ := json.Marshal(h)
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if h.State != "answering" || fields["timeout_ms"] != float64(120000) || h.InputBytes != bytes || h.ActiveSubject != "fixture" {
		t.Fatalf("wrong active request metadata: %+v; serialized bytes=%d", h, bytes)
	}
	if h = s.Health(); h.State != "idle" || h.ActiveSubject != "" {
		t.Fatalf("stale active task metadata: %+v", h)
	}
}

type preparingSink struct {
	memSink
	entered, release chan struct{}
}

func (s *preparingSink) TrendFor(string, string) model.TrendContext {
	close(s.entered)
	<-s.release
	return model.TrendContext{}
}

func TestTaskDeadlineIncludesEvidencePreparation(t *testing.T) {
	requests := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		w.Write([]byte(`{"choices":[{"message":{"content":"{}"}}]}`))
	}))
	defer srv.Close()
	sink := &preparingSink{entered: make(chan struct{}), release: make(chan struct{})}
	s := New(Config{Enabled: true, Endpoint: srv.URL, Timeout: 20 * time.Millisecond}, sink)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.process(context.Background(), task{kind: "flag", flag: model.Flag{ID: "fixture"}})
	}()
	<-sink.entered
	h := s.Health()
	time.Sleep(40 * time.Millisecond)
	close(sink.release)
	<-done
	if h.State != "preparing" {
		t.Errorf("evidence preparation mislabeled: %+v", h)
	}
	select {
	case <-requests:
		t.Fatal("model contacted after whole-task deadline expired")
	default:
	}
}
