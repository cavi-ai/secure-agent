package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestProxyEgressRefusalFlagsTheSession(t *testing.T) {
	c := newTestCorrelator(t)
	flags := c.Observe(event.Event{
		Kind: event.KindProxyHit, TS: time.Now(), PID: 4242, SessionID: "sess-1",
		RemoteHost: "paste.example.net", RemotePort: 443,
		Detail: "proxy-untrusted-egress: paste.example.net after untrusted content (web: https://evil.example/page)",
	})
	if len(flags) != 1 {
		t.Fatalf("flags = %+v", flags)
	}
	f := flags[0]
	if f.Rule != "proxy-untrusted-egress" || f.SessionID != "sess-1" || f.Severity != 3 {
		t.Fatalf("flag = %+v", f)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Sub != "untrusted-egress" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
}
