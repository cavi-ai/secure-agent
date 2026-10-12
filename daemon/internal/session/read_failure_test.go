package session

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestWorkspaceLookupReportsUnavailableEvidence(t *testing.T) {
	r, st := testResolver(t, fakeProcs{})
	st.Close()
	if workspace := r.WorkspaceFor("missing"); workspace != "" {
		t.Fatalf("unavailable workspace = %q", workspace)
	}
	h := st.WriteHealth()
	if h.ReadFailures != 1 || !slices.Equal(h.ReadActive, []string{"session lookup"}) {
		t.Fatalf("failed identity lookup hidden from evidence health: %+v", h)
	}
}

type unavailableSessionStore struct{ *store.Store }

func (s unavailableSessionStore) GetSession(string) (model.Session, bool, error) {
	return model.Session{}, false, errors.New("identity unavailable")
}

func TestUnavailableIdentityCannotAdoptOrPromoteSession(t *testing.T) {
	r, st := testResolver(t, fakeProcs{})
	r.st = unavailableSessionStore{st}
	if r.adoptsByScopeLocked("unknown", 100, "codex", "/repo") {
		t.Fatal("failed lookup treated as a rootless session")
	}
	old := model.Session{ID: "provisional", Confidence: model.ConfProcessTree, RootPID: 100}
	r.deferred[old.ID] = old
	r.byScope[scopeKey("codex", "/repo")] = old.ID
	r.byRoot[100] = old.ID
	r.NoteTranscriptSighting(TranscriptSighting{ID: "transcript", Harness: "codex", Workspace: "/repo", TS: time.Now()})
	if r.byScope[scopeKey("codex", "/repo")] != old.ID || r.byRoot[100] != old.ID || r.deferred[old.ID].ID != old.ID {
		t.Fatal("unavailable transcript identity changed session ownership")
	}
}

func TestPermissionIdentityFailsClosedWhenSessionLookupFails(t *testing.T) {
	started := time.Now().Add(-time.Hour)
	r, st := testResolver(t, fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", CWD: "/repo", StartTime: started},
		200: {PID: 200, PPID: 100, Exe: "/usr/bin/python3", CWD: "/repo", StartTime: started.Add(time.Second)},
	})
	e := event.Event{Kind: event.KindFileOpen, PID: 100, TS: time.Now()}
	id := r.Resolve(&e)
	st.Close()
	if _, ok := r.PermissionIdentity(200, id); ok {
		t.Fatal("peer bound to a session whose row could not be read")
	}
	if h := st.WriteHealth(); !slices.Contains(h.ReadActive, "session lookup") {
		t.Fatalf("failed identity lookup hidden from read health: %+v", h)
	}
}
