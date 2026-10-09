package correlate

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"testing"
	"time"
)

func TestScopedExpectedUsesFullReaderEndpointAndSession(t *testing.T) {
	c := newFamilyCorrelator(t)
	now := time.Now().UTC()
	g := model.DecisionScope{Kind: "session", Agent: "cursor", SessionID: "session", Workspace: "/work", ReaderExe: "/usr/bin/cat", ResourcePath: "/work/.env", RuleID: readConnectRule, Operation: "read-connect", Destination: "evil.example:443", IdentityBasis: "observed-session", CreatedAt: now.Add(-time.Second)}
	c.SetScopedExpected(func(q []model.DecisionScope, pid int32) bool {
		if pid != 42 {
			return false
		}
		for _, v := range q {
			v.Workspace = "/work"
			if !g.Matches(v, now) {
				return false
			}
		}
		return len(q) > 0
	})
	r := readMark{sessionID: "session", path: g.ResourcePath, exe: g.ReaderExe, pid: 42, kind: event.KindFileOpen, at: now}
	cm := connMark{sessionID: "session", host: "evil.example", port: 443, pid: 42, at: now}
	if !c.expectedLocked("cursor", []readMark{r}, cm, now) {
		t.Fatal("matching permission ignored")
	}
	changed := cm
	changed.port = 8443
	if c.expectedLocked("cursor", []readMark{r}, changed, now) {
		t.Fatal("permission crossed endpoint port")
	}
	changedReader := r
	changedReader.exe = "/other/cat"
	if c.expectedLocked("cursor", []readMark{changedReader}, cm, now) {
		t.Fatal("permission crossed executable path")
	}
	changed = cm
	changed.sessionID = "other"
	if c.expectedLocked("cursor", []readMark{r}, changed, now) {
		t.Fatal("permission crossed session")
	}
	changedReader = r
	changedReader.sessionID = ""
	if c.expectedLocked("cursor", []readMark{changedReader}, cm, now) {
		t.Fatal("unknown read identity became reusable")
	}
}

func TestScopedMismatchNewSessionIsNotFoldedIntoOldReview(t *testing.T) {
	c := newFamilyCorrelator(t)
	now := time.Now().UTC()
	r := readMark{sessionID: "first", path: "/work/.env", exe: "/usr/bin/cat", pid: 42, kind: event.KindFileOpen, at: now}
	cm := connMark{sessionID: "first", host: "evil.example", port: 443, pid: 42, at: now.Add(time.Second)}
	first := c.readThenConnectLocked(event.Event{TS: now, PID: 42, SessionID: "first"}, "cursor", 42, []readMark{r}, []connMark{cm})
	r.at = now.Add(2 * time.Second)
	r.sessionID = "second"
	cm.sessionID = "second"
	second := c.readThenConnectLocked(event.Event{TS: r.at, PID: 42, SessionID: "second"}, "cursor", 42, []readMark{r}, []connMark{cm})
	if len(first) != 1 || len(second) != 1 || second[0].SessionID != "second" {
		t.Fatal("new session folded into prior evidence context")
	}
}

func TestScopedMixedSessionEvidenceHasNoReusableIdentity(t *testing.T) {
	c := newFamilyCorrelator(t)
	now := time.Now().UTC()
	r := readMark{sessionID: "first", path: "/work/.env", exe: "/usr/bin/cat", pid: 42, kind: event.KindFileOpen, at: now}
	cm := connMark{sessionID: "second", host: "evil.example", port: 443, pid: 42, at: now.Add(time.Second)}
	flags := c.readThenConnectLocked(event.Event{TS: now, PID: 42, SessionID: "second"}, "cursor", 42, []readMark{r}, []connMark{cm})
	if len(flags) != 1 || flags[0].SessionID != "" {
		t.Fatal("mixed-session evidence inherited reusable identity")
	}
	if _, err := model.ReadConnectScopes(flags[0]); err == nil {
		t.Fatal("mixed-session evidence granted future permission")
	}
}
