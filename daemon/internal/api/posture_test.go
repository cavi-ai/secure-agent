package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

func TestPostureAllClearWhenNothingPending(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/posture")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("posture get: %v status=%v", err, resp.StatusCode)
	}
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "all-clear" || p.NeedsYou != 0 {
		t.Fatalf("posture = %+v, want all-clear/0", p)
	}
}

func TestPostureCriticalFlagDrivesState(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture2_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, TS: time.Now(), Evidence: []string{"read .env then connected"}})
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "critical" || p.NeedsYou != 1 {
		t.Fatalf("posture = %+v, want critical/1", p)
	}
	if p.Items[0].Title != "Agent read a secret, then connected out" {
		t.Fatalf("title = %q, want human phrasing", p.Items[0].Title)
	}
	if p.Summary == "" {
		t.Fatal("summary must be populated")
	}
}

func TestPostureCountsUninspectedEgressAndDeadCollectors(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status {
		return Status{
			Running:           true,
			UninspectedEgress: 3,
			Collectors:        []supervise.Health{{Name: "eslogger", Running: false, LastError: "exit 1"}},
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.State != "attention" || p.NeedsYou != 2 {
		t.Fatalf("posture = %+v, want attention/2", p)
	}
	kinds := map[string]bool{}
	for _, it := range p.Items {
		kinds[it.Kind] = true
	}
	if !kinds["uninspected_egress"] || !kinds["collector_down"] {
		t.Fatalf("expected egress + collector items, got %+v", p.Items)
	}
	var egressTitle string
	for _, it := range p.Items {
		if it.Kind == "uninspected_egress" {
			egressTitle = it.Title
		}
	}
	if !strings.Contains(egressTitle, "3 connections") {
		t.Fatalf("egress title = %q", egressTitle)
	}
}

func TestPostureOldFlagsDoNotCount(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_posture4_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutFlag(model.Flag{ID: "old", Rule: "keychain-access", Severity: 3, TS: time.Now().Add(-48 * time.Hour)})
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, _ := cl.Get("http://unix/posture")
	var p Posture
	decodeInto(t, resp, &p)
	if p.NeedsYou != 0 {
		t.Fatalf("48h-old flag counted: %+v", p)
	}
}

// decodeInto is a tiny helper so tests stay flat.
func decodeInto(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := jsonDecode(resp.Body, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestIncidentStatusEndpointRoundTrip(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_incstat_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	st := testStore(t)
	st.PutIncident(model.IncidentReport{ID: "inc-x", Summary: "leak", Risk: "CRITICAL"})
	a := New(sock, st, &fakeKiller{}, func() Status { return Status{Running: true} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	// Acknowledge.
	resp, err := cl.Post("http://unix/incidents/status", "application/json",
		strings.NewReader(`{"id":"inc-x","status":"acknowledged"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ack: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Resolve with note.
	resp, err = cl.Post("http://unix/incidents/status", "application/json",
		strings.NewReader(`{"id":"inc-x","status":"resolved","note":"rotated"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("resolve: %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// GET by id carries the workflow.
	resp, _ = cl.Get("http://unix/incidents?id=inc-x")
	var out struct {
		Workflow store.IncidentWorkflow `json:"workflow"`
	}
	decodeInto(t, resp, &out)
	if out.Workflow.Status != "resolved" || out.Workflow.ResolutionNote != "rotated" {
		t.Fatalf("workflow = %+v", out.Workflow)
	}

	// Unknown id → 404.
	resp, _ = cl.Post("http://unix/incidents/status", "application/json",
		strings.NewReader(`{"id":"ghost","status":"resolved"}`))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ghost status=%d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}
