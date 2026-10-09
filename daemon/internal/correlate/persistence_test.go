package correlate

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestRejectedPersistenceReleasesRuleSuppression(t *testing.T) {
	for _, e := range []event.Event{
		{Kind: event.KindExec, PID: 201, ExePath: "/usr/bin/security"},
		{Kind: event.KindTCCModify, PID: 201, Detail: "privacy"},
		{Kind: event.KindFileOpen, PID: 201, Path: homePath(t, "Library/Keychains/login.keychain-db")},
		{Kind: event.KindProxyHit, PID: 201, RemoteHost: "evil.example.com", Detail: "proxy-secret-leak"},
		{Kind: event.KindTranscriptHit, Path: "/transcript.jsonl", Detail: "codex:pattern:secret"},
	} {
		t.Run(e.Kind.String(), func(t *testing.T) {
			c := newFamilyCorrelator(t)
			e.TS = time.Unix(1700000000, 0)
			flags := c.Observe(e)
			if len(flags) != 1 {
				t.Fatalf("initial flags: %+v", flags)
			}
			c.ResolvePersistence(flags[0].ID, false)
			e.TS = e.TS.Add(time.Second)
			flags = c.Observe(e)
			if len(flags) != 1 {
				t.Fatalf("rejected flag prevented recovery: %+v", flags)
			}
			c.ResolvePersistence(flags[0].ID, true)
			e.TS = e.TS.Add(time.Second)
			if flags = c.Observe(e); len(flags) != 0 {
				t.Fatalf("saved flag no longer suppresses repeats: %+v", flags)
			}
		})
	}
}

func TestRejectedEscalationPreservesSavedReadFinding(t *testing.T) {
	c := newFamilyCorrelator(t)
	at := time.Unix(1700000000, 0)
	ghReads(c, t, event.KindFileOpen, at)
	first := connectTo(c, 200, "evil.example.com", at.Add(time.Second))
	if len(first) != 1 || first[0].Severity != 2 {
		t.Fatal(first)
	}
	c.ResolvePersistence(first[0].ID, true)
	ghReads(c, t, event.KindFileOpen, at.Add(2*time.Minute))
	stronger := connectTo(c, 201, "evil.example.com", at.Add(2*time.Minute+time.Second))
	if len(stronger) != 1 || stronger[0].Severity != 3 {
		t.Fatal(stronger)
	}
	c.ResolvePersistence(stronger[0].ID, false)
	var repeatID string
	c.SetOnRepeat(func(id string, _ time.Time) { repeatID = id })
	if flags := connectTo(c, 200, "evil.example.com", at.Add(2*time.Minute+2*time.Second)); len(flags) != 0 || repeatID != first[0].ID {
		t.Fatalf("failed escalation displaced saved finding: flags=%+v repeat=%s", flags, repeatID)
	}
}

func TestPersistenceResolutionKeepsOtherFlagsSuppressed(t *testing.T) {
	c := newFamilyCorrelator(t)
	at := time.Unix(1700000000, 0)
	connectTo(c, 201, "evil.example.com", at)
	read := event.Event{Kind: event.KindFileOpen, PID: 201, TS: at.Add(time.Second),
		Path: homePath(t, "Library/Keychains/login.keychain-db"), ExePath: "/bin/cp"}
	flags := c.Observe(read)
	if len(flags) != 2 {
		t.Fatalf("expected independent keychain and read-connect flags: %+v", flags)
	}
	for _, f := range flags {
		c.ResolvePersistence(f.ID, f.Rule != readConnectRule)
	}
	read.TS = read.TS.Add(time.Second)
	flags = c.Observe(read)
	if len(flags) != 1 || flags[0].Rule != readConnectRule {
		t.Fatalf("resolution changed another flag's suppression: %+v", flags)
	}
}
