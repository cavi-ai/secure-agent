package daemon

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/session"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/supervise"
)

// The Hermes collector built for the daemon reads hermes_home and lands each
// session in the store as a hermes session with its repo, branch and parent.
func TestHermesCollectorWiring(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), filepath.Join(dir, "e.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	root := filepath.Join(dir, "hermes")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "state.db")+"?_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, parent_session_id TEXT, started_at REAL,
		  ended_at REAL, cwd TEXT, git_branch TEXT, git_repo_root TEXT, input_tokens INTEGER)`,
		`CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, timestamp REAL, token_count INTEGER)`,
		`INSERT INTO sessions VALUES ('h-1', 'cli', 'gpt-5', 'h-0', 1790150400, NULL, '/nonexistent/proj', 'main', '/nonexistent/proj', 0)`,
		`INSERT INTO messages VALUES (1, 'h-1', 'user', 'x', 1790150401, 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.Config{HermesHome: root, DBPath: filepath.Join(dir, "e.db")}
	h := newHermesCollector(cfg, bus.New(8), supervise.NewRegistry(), session.NewResolver(st, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h.Run(ctx) // one poll, then ctx is done

	s, ok := st.GetSession("h-1")
	if !ok || s.Harness != "hermes" || s.Workspace != "/nonexistent/proj" || s.Repo != "proj" || s.Branch != "main" || s.ParentID != "h-0" {
		t.Fatalf("session = %+v (ok=%v)", s, ok)
	}
	if hs := h.Status(); len(hs.DBs) != 1 || hs.DBs[0].Watermark != 1 {
		t.Fatalf("status = %+v", hs)
	}
}
