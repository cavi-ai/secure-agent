package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/testutil"
)

// A sighting delivered through the scanner's callback lands in the store with
// its harness and origin.
func TestTranscriptSightingWiring(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	seen := transcriptSighting(session.NewResolver(st, nil))

	seen(collect.TraceSession{ID: "c-1", Harness: "codex", Workspace: "/nonexistent/proj", Origin: "quill (openclaw)", At: time.Now()})
	seen(collect.TraceSession{ID: "cl-1", Harness: "claude", Workspace: "/nonexistent/proj", At: time.Now()})

	s, ok := testutil.Lookup[model.Session](t)(st.GetSession("c-1"))
	if !ok || s.Harness != "codex" || s.Workspace != "/nonexistent/proj" || s.Origin != "quill (openclaw)" {
		t.Fatalf("codex session = %+v (ok=%v)", s, ok)
	}
	s, ok = testutil.Lookup[model.Session](t)(st.GetSession("cl-1"))
	if !ok || s.Harness != "claude" || s.Origin != "" {
		t.Fatalf("claude session = %+v (ok=%v)", s, ok)
	}
}
