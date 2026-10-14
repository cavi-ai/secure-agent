package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/forwarder"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/hermes"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/openclaw"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/opencode"
	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Exercise a real recorder process, collector, SQLite store and read API across
// recorder unavailability and recovery. Native notification input is a fixture;
// live app-server validation is separate from this deterministic regression.
func TestNativeForwardersRecoverThroughRecorderAndSessionAPI(t *testing.T) {
	for _, harness := range []string{"codex", "openclaw", "hermes", "opencode"} {
		for _, durable := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/durable=%v", harness, durable), func(t *testing.T) { testNativeForwarderRecovery(t, harness, durable) })
		}
	}
}

type nativeForwarder interface {
	Submit([]byte) (string, error)
	SetSourceState(string) error
	Snapshot() forwarder.Snapshot
	Run(context.Context) error
	Close() error
}

func testNativeForwarderRecovery(t *testing.T, harness string, durable bool) {
	root := t.TempDir()
	binary := filepath.Join(root, "recorder")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary+"-held", "github.com/cavi-ai/secure-agent/cmd/secure-agent")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build recorder: %v\n%s", err, out)
	}
	output := filepath.Join(root, "activity.jsonl")
	if err := os.WriteFile(output, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)
	st.TrackHookIngestion()
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	scanner := collect.NewTranscriptScanner(b, []string{output})
	scanner.OffsetStatePath = filepath.Join(root, "offsets.json")
	ready := make(chan struct{}, 1)
	scanner.OnCheckpointWrite = func(err error) {
		if err == nil {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
	scanner.OnHookAccepted = st.NoteHookAccepted
	scanner.OnHookRejected = st.NoteHookRejected
	scanner.OnHookForwarder = st.NoteHookForwarder
	scanCtx, stopScan := context.WithCancel(ctx)
	scanDone := make(chan error, 1)
	go func() { scanDone <- scanner.Run(scanCtx) }()
	defer func() { stopScan(); <-scanDone }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not seed source")
	}
	sink := forwarder.Recorder{Executable: binary, Output: output}
	cfg := forwarder.Config{Sender: sink, Capacity: 1, RetryInterval: 20 * time.Millisecond}
	if durable {
		cfg.OutboxDir = filepath.Join(root, "outbox")
	}
	var c nativeForwarder
	var err error
	if harness == "codex" {
		c, err = forwarder.NewCodex(cfg)
	} else {
		cfg.Harness = harness
		decoder := map[string]hookrun.Decoder{"openclaw": openclaw.Decoder{}, "hermes": hermes.Decoder{}, "opencode": opencode.Decoder{}}[harness]
		c, err = forwarder.NewAdapter(cfg, decoder)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetSourceState("connected"); err != nil {
		t.Fatal(err)
	}
	native := nativeBlockedCompletion(harness, "one")
	id, err := c.Submit(native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Submit(nativeBlockedCompletion(harness, "two")); err != forwarder.ErrFull {
		t.Fatalf("overflow: %v", err)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- c.Run(workerCtx) }()
	defer func() { stopWorker(); <-workerDone }()
	deadline := time.Now().Add(5 * time.Second)
	for c.Snapshot().DeliveryFailures == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s := c.Snapshot(); s.State != "error" || s.Pending != 1 || s.Dropped != 1 || !s.ReportError {
		t.Fatalf("outage: %+v", s)
	}
	if durable {
		if c.Snapshot().Persisted != 1 {
			t.Fatal("delivery attempted before local persistence")
		}
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(`{"type":"hook_run","run_id":"torn-prefix`)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(binary+"-held", binary); err != nil {
		t.Fatal(err)
	}
	put := func(wantChange bool) {
		t.Helper()
		select {
		case e := <-sub:
			if e.Kind != event.KindHookRun || e.CallID != id {
				t.Fatalf("forwarded event: %+v", e)
			}
			if w, err := st.PutEvent(e); err != nil || w.Changed != wantChange {
				t.Fatalf("store delivery: %+v %v", w, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("completion did not reach collector")
		}
	}
	put(true)
	var replay []byte
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private")) {
		t.Fatal("raw notification persisted")
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if r, ok, err := hookrun.DecodeRecord(line); ok && err == nil && r.ID == id {
			replay = bytes.Clone(line)
		}
	}
	if len(replay) == 0 {
		t.Fatal("original delivery identity was lost")
	}
	// An uncertain acknowledgement may cause the same accepted ID to be sent
	// again. Replaying through the real recorder must not add hook history.
	resend := sink.Send
	if durable {
		resend = sink.SendDurable
	}
	if err := resend(ctx, replay); err != nil {
		t.Fatal(err)
	}
	put(false)
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h := st.HookIngestion()
		if len(h.Forwarders) == 1 && h.Forwarders[0].Report.State == "connected" && h.Forwarders[0].Report.Pending == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	sock := fmt.Sprintf("/tmp/sa_forwarder_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(Deps{SocketPath: sock, Store: st, Status: func() Status { return Status{Running: true} }})
	apiCtx, stopAPI := context.WithCancel(ctx)
	apiDone := make(chan error, 1)
	go func() { apiDone <- a.Serve(apiCtx) }()
	defer func() { stopAPI(); <-apiDone }()
	waitForSocket(t, sock)
	resp, err := unixClient(sock).Get("http://unix/sessions/forwarded-session/hooks")
	if err != nil {
		t.Fatal(err)
	}
	var hooks []store.HookSummary
	decodeInto(t, resp, &hooks)
	if len(hooks) != 1 || hooks[0].Runs != 1 || hooks[0].Blocks != 1 || hooks[0].HandlerID == "" {
		t.Fatalf("history duplicated or attribution lost: %+v", hooks)
	}
	resp, err = unixClient(sock).Get("http://unix/status")
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	decodeInto(t, resp, &status)
	if status.HookIngestion == nil || len(status.HookIngestion.Forwarders) != 1 {
		t.Fatal("forwarder report missing")
	}
	r := status.HookIngestion.Forwarders[0].Report
	if r.State != "connected" || r.Pending != 0 || r.DeliveryFailures < 1 || r.Dropped != 1 || r.Health == nil || r.Health.SourceState != "connected" || r.Health.DeliveryError != "" || r.Health.CaptureError != "" {
		raw, _ := json.Marshal(r)
		t.Fatalf("recovery erased evidence: %s", raw)
	}
	if durable && (r.Health.Outbox == nil || r.Health.Outbox.Persisted != 0 || r.Health.Outbox.Error != "") || !durable && r.Health.Outbox != nil {
		t.Fatalf("persistence health mismatch: %+v", r.Health)
	}
}

func nativeBlockedCompletion(harness, id string) []byte {
	if harness == "codex" {
		return []byte(`{"method":"hook/completed","params":{"threadId":"forwarded-session","run":{"id":"stop:0:/private/hooks.json","eventName":"stop","status":"blocked","completedAt":1791882001,"durationMs":7,"entries":[{"kind":"feedback","text":"private feedback"}]}}}`)
	}
	eventName, result, extra := "before_tool_call", `{"block":true,"blockReason":"private feedback"}`, ""
	switch harness {
	case "hermes":
		eventName, result = "pre_tool_call", `{"action":"block","message":"private feedback"}`
	case "opencode":
		eventName, result, extra = "permission.evaluate", `{"effect":"deny","message":"private feedback"}`, `,"protocol":"opencode-v2","before":{"effect":"allow"}`
	}
	return []byte(fmt.Sprintf(`{"type":"hook_completed","version":2,"harness":%q,"id":%q,"session_id":"forwarded-session","ts":"2026-10-13T10:00:01Z","event":%q,"state":"completed","duration_ms":7,"result":%s,"evidence":{"handler_id":"handler-1"}%s}`, harness, id, eventName, result, extra))
}
