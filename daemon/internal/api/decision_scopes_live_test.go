package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
)

// Exercise the real process source, kernel Unix peer credentials, resolver,
// SQLite and HTTP handlers together; no client-supplied identity is attestation.
func TestGuardKernelPeerScopeLifecycle(t *testing.T) {
	st := testStore(t)
	source := agents.NewProcSource()
	pid := int32(os.Getpid())
	info, ok := source.Info(pid)
	if !ok || info.Exe == "" || info.CWD == "" || info.StartTime.IsZero() {
		t.Fatal("live process identity unavailable")
	}
	tagger := agents.New(config.Config{Agents: []config.AgentDef{{Name: "scope-proof", Match: []string{info.Exe}}}}, source)
	resolver := session.NewResolver(st, tagger)
	e := event.Event{Kind: event.KindFileOpen, PID: pid, TS: time.Now()}
	resolver.Resolve(&e)
	resolver.HandleHandshake(session.Handshake{SessionID: "scope-live", Harness: "scope-proof", Workspace: info.CWD, PID: pid, TS: time.Now()})
	a := New(Deps{Store: st, Guard: guard.NewBroker(2 * time.Second), GuardIdentity: resolver.PermissionIdentity, PeerChecker: NewPeerChecker(), UIPID: pid})
	dir, err := os.MkdirTemp("", "scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "scope.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- a.ServeListener(ctx, listener) }()
	t.Cleanup(func() { cancel(); listener.Close(); <-serverDone })
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	post := func(route, body string) (string, error) {
		resp, err := client.Post("http://unix"+route, "application/json", strings.NewReader(body))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		var out json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return string(out), err
	}
	body := `{"agent":"scope-proof","session_id":"scope-live","tool":"Read","path":"/work/.env","rule_id":"env"}`
	answer := make(chan string, 1)
	fail := make(chan error, 1)
	go func() { s, err := post("/guard/decision", body); answer <- s; fail <- err }()
	deadline := time.Now().Add(time.Second)
	var p guard.Pending
	for time.Now().Before(deadline) {
		if pending := a.guardBroker.Pending(); len(pending) > 0 {
			p = pending[0]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if p.ID == "" || len(p.AvailableScopes) != 4 {
		t.Fatalf("kernel-bound request lacks bounded choices: %+v", p)
	}
	if _, err = post("/guard/resolve", `{"id":"`+p.ID+`","verdict":"allow","scope":"session"}`); err != nil {
		t.Fatal(err)
	}
	if out, err := <-answer, <-fail; err != nil || !strings.Contains(out, `"scope":"session"`) {
		t.Fatalf("live decision: %s %v", out, err)
	}
	if out, err := post("/guard/decision", body); err != nil || !strings.Contains(out, `"reason":"saved-permission"`) {
		t.Fatalf("live cached grant: %s %v", out, err)
	}
	if err = st.EndSession("scope-live", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok = resolver.PermissionIdentity(pid, "scope-live"); ok {
		t.Fatal("ended session retained live permission identity")
	}
}
