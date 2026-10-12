package session

import (
	"errors"
	"slices"
	"testing"
	"time"

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

func (s unavailableSessionStore) GetSessionResult(string) (model.Session, bool, error) {
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
