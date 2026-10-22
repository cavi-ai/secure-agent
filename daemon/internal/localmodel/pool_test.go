package localmodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackgroundBudgetLeavesForegroundAvailable(t *testing.T) {
	p := New()
	p.windowStarted = time.Now()
	p.backgroundUsed = 2 * time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &waiter{ctx: ctx, cancel: cancel, ready: make(chan error, 1)}
	if err := p.acquire(w); !errors.Is(err, ErrBudget) {
		t.Fatalf("background budget was not enforced: %v", err)
	}
	w.foreground = true
	if err := p.acquire(w); err != nil {
		t.Fatal(err)
	}
	p.release(w)
}

// countingTransport counts the round trips in flight beneath the pool: one
// is in flight from RoundTrip until it fails, or its body ends or closes.
type countingTransport struct {
	base         http.RoundTripper
	active, peak atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	n := c.active.Add(1)
	for p := c.peak.Load(); n > p && !c.peak.CompareAndSwap(p, n); p = c.peak.Load() {
	}
	resp, err := c.base.RoundTrip(r)
	if err != nil {
		c.active.Add(-1)
		return nil, err
	}
	resp.Body = &countedBody{ReadCloser: resp.Body, done: func() { c.active.Add(-1) }}
	return resp, nil
}

type countedBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *countedBody) Read(v []byte) (int, error) {
	n, err := b.ReadCloser.Read(v)
	if err != nil {
		b.once.Do(b.done)
	}
	return n, err
}

func (b *countedBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.done); return err }

// Overlap is counted where the pool serializes: the requests it lets through.
// A server only sees a cancelled request end when it notices the closed
// connection, which can be after the pool has started the next one.
func TestSharedPoolSerializesAndCancelsInference(t *testing.T) {
	entered := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer srv.Close()
	p := New()
	counted := &countingTransport{base: srv.Client().Transport}
	fg := &http.Client{Transport: p.Transport(counted, true)}
	bg := &http.Client{Transport: p.Transport(counted, false)}
	done := make(chan struct{}, 2)
	call := func(c *http.Client, ctx context.Context) {
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"test","messages":[]}`))
		_, _ = c.Do(req)
		done <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go call(bg, ctx)
	<-entered
	go call(fg, ctx)
	deadline := time.Now().Add(time.Second)
	for p.Snapshot().Queued != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.Snapshot().Queued != 1 {
		t.Fatal("foreground was not queued behind active inference")
	}
	p.PauseBackground(true)
	<-entered
	cancel()
	<-done
	<-done
	if peak := counted.peak.Load(); peak != 1 {
		t.Fatalf("overlapping requests: %d", peak)
	}
	if p.Snapshot().Active {
		t.Fatal("cancelled request retained its lease")
	}
}

func TestOllamaNativeControlsAndToolRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			io.WriteString(w, `{"version":"0.15.0"}`)
		case "/api/chat":
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			if in["keep_alive"] != "2m" || in["options"].(map[string]any)["num_ctx"] != float64(ContextTokens) {
				t.Error("missing residency/context controls")
			}
			io.WriteString(w, `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"inspect_snapshot","arguments":{}}}]},"done":true,"done_reason":"stop","prompt_eval_count":10,"eval_count":2}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &http.Client{Transport: New().OllamaTransport(srv.Client().Transport, true)}
	resp, err := c.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"hello"}],"max_tokens":100}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID       string
					Function struct{ Arguments string } `json:"function"`
				} `json:"tool_calls"`
			}
		}
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
		}
	}
	if err = json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Choices) != 1 || len(out.Choices[0].Message.ToolCalls) != 1 || out.Choices[0].Message.ToolCalls[0].Function.Arguments != "{}" || out.Usage.PromptTokens != 10 {
		t.Fatalf("native response not adapted: %+v %v", out, err)
	}
}
