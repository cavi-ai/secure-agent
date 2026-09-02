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

func TestDarwinPeerCheckerResolvesSelf(t *testing.T) {
	a, b := socketpair(t)
	defer a.Close()
	defer b.Close()

	cred, err := DarwinPeerChecker{}.PeerCred(a)
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
	a := New(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	// Checker set: all connections resolve to this process (owner uid).
	// Pin this process as the menubar UI; the request must then be allowed
	// and reach the killer (a foreign uid would be refused by classify).
	a.SetPeers(loopbackChecker{DarwinPeerChecker{}}, nil)
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
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetPeers(loopbackChecker{DarwinPeerChecker{}}, nil)
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Get("http://unix/status")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status as owner: %v status=%v", err, resp.StatusCode)
	}
}

func TestGateAllowsGuardDecisionForOwner(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_gate3_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := New(sock, testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.SetGuard(newTestBroker())
	a.SetPeers(loopbackChecker{DarwinPeerChecker{}}, nil)
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
	a := New(sock, testStore(t), fk, func() Status { return Status{Running: true} })
	// No peer checker (open, as in tests) but the agent allowlist is active —
	// the kill restriction is independent of peer gating.
	a.SetAgentPIDs(func() map[int32]struct{} { return map[int32]struct{}{42: {}} })
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)

	cl := unixClient(sock)
	resp, err := cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":7}`))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("kill non-agent pid: %v status=%v, want 403", err, resp.StatusCode)
	}
	if fk.killed != 0 {
		t.Fatal("killer must not fire for a non-agent pid")
	}

	resp, err = cl.Post("http://unix/kill", "application/json", strings.NewReader(`{"pid":42}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("kill tagged agent pid: %v status=%v", err, resp.StatusCode)
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
