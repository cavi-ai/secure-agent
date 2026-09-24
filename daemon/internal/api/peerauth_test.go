package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/guard"
)

// realPeerChecker resolves credentials against the test process's own sockets,
// so a loopback request inside the test is classified by the real kernel path.
type loopbackChecker struct{ inner PeerChecker }

func (l loopbackChecker) PeerCred(c net.Conn) (PeerCred, error) {
	return l.inner.PeerCred(c)
}

func TestPeerCheckerResolvesSelf(t *testing.T) {
	a, b := socketpair(t)
	defer a.Close()
	defer b.Close()

	cred, err := NewPeerChecker().PeerCred(a)
	if err != nil {
		t.Fatalf("PeerCred: %v", err)
	}
	// The peer end was created by this process via socketpair(2), but on macOS
	// LOCAL_PEEREPID reports the pid that created the *other* end — this same
	// process here. UID must always be ours.
	if cred.UID != os.Getuid() {
		t.Fatalf("uid = %d, want %d", cred.UID, os.Getuid())
	}
	_ = b
}

func socketpair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	// Short path: sockaddr_un is limited to ~104 bytes on macOS.
	sock := fmt.Sprintf("/tmp/sa_pair_%d.sock", time.Now().UnixNano())
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(sock)
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := listener.Accept()
		ch <- result{c, err}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ar := <-ch
	if ar.err != nil {
		t.Fatal(ar.err)
	}
	return ar.c, client
}

func TestGateAllowsPinnedUIMutation(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_gate_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	// Checker set: all connections resolve to this process (owner uid).
	// Pin this process as the menubar UI; the request must then be allowed
	// and reach the killer (a foreign uid would be refused by classify).
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, nil)
	a.peerRole.UIPID = int32(os.Getpid())
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kill as pinned UI: status=%d, want 200", resp.StatusCode)
	}
	if fk.killed != 7 {
		t.Fatalf("killer got pid %d, want 7", fk.killed)
	}
}

func TestGateAllowsOwnerReadsWithCheckerSet(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_gate2_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, nil)
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/status")
	if err != nil {
		t.Fatalf("status as owner: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
}

func TestGateAllowsGuardDecisionForOwner(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_gate3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.guardBroker = newTestBroker()
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, nil)
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	// Owner may also post decisions (fail-open to owner for hook-less flows).
	// Use a very short deadline via a tiny broker timeout — but the broker
	// blocks; instead verify the endpoint is reachable (not 403) by sending a
	// malformed payload that fails validation *before* broker blocking.
	cl := unixClient(sock)
	req, _ := http.NewRequest("POST", "http://unix/guard/decision", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("guard decision validation: status=%d, want 400 (not 403)", resp.StatusCode)
	}
}

func TestKillEndpointRejectsNonAgentPIDWhenAllowlistSet(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_kill_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	// No peer checker (open, as in tests) but the agent allowlist is active —
	// the kill restriction is independent of peer gating.
	a.agentPIDs = func() map[int32]struct{} { return map[int32]struct{}{42: {}} }
	if a.peerRole != nil {
		a.peerRole.AgentPIDs = func() map[int32]struct{} { return map[int32]struct{}{42: {}} }
	}
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil {
		t.Fatalf("kill non-agent pid: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%v, want 403", resp.StatusCode)
	}
	if fk.killed != 0 {
		t.Fatal("killer must not fire for a non-agent pid")
	}

	resp, err = cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":42}`))
	if err != nil {
		t.Fatalf("kill tagged agent pid: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	if fk.killed != 42 {
		t.Fatalf("killer got pid %d, want 42", fk.killed)
	}
}

// --- helpers shared with this file only ---

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func newTestBroker() *guard.Broker {
	return guard.NewBroker(50 * time.Millisecond)
}

// With the menubar pinned, a same-uid non-UI caller (a shell, a rogue script)
// may read but must not mutate.
func TestGateRejectsNonUIMutationWhenUIPinned(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_pin_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	a.setPeersForTest(NewPeerChecker(), nil)
	a.peerRole.UIPID = int32(os.Getpid()) + 9999 // a pid that is NOT this test process
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/guard/resolve", "application/json",
		strings.NewReader(`{"id":"x","verdict":"allow","scope":"once"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-UI mutation: status=%d, want 403", resp.StatusCode)
	}
	if fk.killed != 0 {
		t.Fatal("killer must not fire")
	}

	// Reads stay available to the owner.
	resp, err = cl.Get("http://unix/status")
	if err != nil {
		t.Fatalf("read as owner when pinned: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v", resp.StatusCode)
	}
	resp.Body.Close()
}

// /mute is in the mutation set: with a UI pinned, an owner-uid shell gets a
// flat 403 while the pinned UI passes — the exact path behind "dismiss
// failed" reports. Pin the whole policy surface for the disposition
// endpoints so a refactor can't silently re-open (or re-close) them.
func TestGateDispositionEndpointsPolicy(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_dispo_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setPeersForTest(NewPeerChecker(), nil)
	a.peerRole.UIPID = int32(os.Getpid()) + 9999 // not this process
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	// Owner (not the pinned UI): mutations 403.
	for _, tc := range []struct{ path, body string }{
		{"/mute", `{"rule":"keychain-access","host":"*"}`},
		{"/flags/acknowledge", `{"flag_id":"abc123"}`},
		{"/allowlist", `{"agent":"cursor","host":"example.com"}`},
		{"/advisor/retriage", `{"flag_id":"abc123"}`},
		{"/resources/control", `{"id":"resource-1","decision":"dismiss"}`},
	} {
		resp, err := cl.Post("http://unix"+tc.path, "application/json", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("POST %s as owner when UI pinned: status=%d, want 403", tc.path, resp.StatusCode)
		}
	}
	del, _ := http.NewRequest(http.MethodDelete, "http://unix/mute?rule=keychain-access&host=api.example.com", nil)
	resp, err := cl.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE /mute as owner when UI pinned: status=%d, want 403", resp.StatusCode)
	}

	// /notify/rules is owner-level (headless/ssh management like
	// DELETE /guard/rules): the owner passes even with a UI pinned.
	resp, err = cl.Post("http://unix/notify/rules", "application/json",
		strings.NewReader(`{"rule":"keychain-access","notify":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// 503 (store unwired here) is fine — the point is the GATE let it through.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("POST /notify/rules as owner must pass the gate (owner-level, like other headless management)")
	}
}

func TestResourcePolicyPutIsPinnedUIMutation(t *testing.T) {
	if !isMutation(http.MethodPut, "/resources/policy") {
		t.Fatal("PUT /resources/policy must require the pinned UI role")
	}
}

// Same set, but through the pinned-UI lens: this process IS the UI, so its
// mutations must clear the gate (they may 400/503 on unwired stores — the
// gate decision is what matters).
func TestGateDispositionEndpointsAsPinnedUI(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_dispoui_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := newTestAPI(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.setPeersForTest(NewPeerChecker(), nil)
	a.peerRole.UIPID = int32(os.Getpid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	for _, tc := range []struct{ path, body string }{
		{"/mute", `{"rule":"keychain-access","host":"*"}`},
		{"/flags/acknowledge", `{"flag_id":"abc123"}`},
		{"/allowlist", `{"agent":"cursor","host":"example.com"}`},
		{"/resources/control", `{"id":"resource-1","decision":"dismiss"}`},
	} {
		resp, err := cl.Post("http://unix"+tc.path, "application/json", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Fatalf("POST %s as pinned UI: got 403 — the menubar's dismiss flow is broken", tc.path)
		}
	}
	del, _ := http.NewRequest(http.MethodDelete, "http://unix/mute?rule=keychain-access&host=api.example.com", nil)
	resp, err := cl.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("DELETE /mute as pinned UI: got 403 — the menubar's unmute is broken")
	}
}

// A tagged agent (hook traffic) may read and ask the guard for decisions,
// but must never mutate. Before authorize() was wired through the role
// methods, agents got 403 on everything — including /guard/decision, which
// broke the directory-guard prompt flow.
func TestGateAgentRolePolicy(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_agent_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	a.guardBroker = newTestBroker()
	// Classify this test process's connections as a tagged agent.
	selfPID := int32(os.Getpid())
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, func() map[int32]struct{} {
		return map[int32]struct{}{selfPID: {}}
	})
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)

	// Reads: allowed.
	resp, err := cl.Get("http://unix/status")
	if err != nil {
		t.Fatalf("agent read /status: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%v, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Guard decision: allowed through the gate (400 = handler validation, not 403).
	req, _ := http.NewRequest("POST", "http://unix/guard/decision", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("agent /guard/decision: status=%d, want 400 (not 403)", resp.StatusCode)
	}

	// Mutations: forbidden for agents even without a UI pin.
	resp, err = cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":42}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent /kill: status=%d, want 403", resp.StatusCode)
	}
	if fk.killed != 0 {
		t.Fatal("killer must not fire for an agent-role caller")
	}

	// DELETE /guard/rules: owner-level, forbidden for agents.
	req, _ = http.NewRequest("DELETE", "http://unix/guard/rules?agent=x&rule_id=y", nil)
	resp, err = cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent DELETE /guard/rules: status=%d, want 403", resp.StatusCode)
	}
}

// No UI pin (direct launch): owner-uid mutation still works for headless use.
func TestGateAllowsOwnerMutationWithoutUIPin(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_nopin_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	fk := &fakeKiller{}
	a := newTestAPI(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	a.setPeersForTest(NewPeerChecker(), nil)
	// UIPID stays 0.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/incidents/status", "application/json",
		strings.NewReader(`{"id":"inc-y","status":"acknowledged"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// 404 (unknown incident) proves the gate let it through to the handler.
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("owner mutation without pin: status=%d, want 404 (handler reached)", resp.StatusCode)
	}
}
