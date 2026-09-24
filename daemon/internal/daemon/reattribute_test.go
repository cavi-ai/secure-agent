package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type mapProcSource map[int32]agents.ProcInfo

func (m mapProcSource) List() []agents.ProcInfo {
	out := make([]agents.ProcInfo, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	return out
}

func (m mapProcSource) Info(pid int32) (agents.ProcInfo, bool) {
	p, ok := m[pid]
	return p, ok
}

// A flag stamped "untagged:" before the tagger caught up takes the agent's
// name once Refresh tags the pid, and the console hears it as a flag delta.
func TestTaggerCatchUpReattributesUntaggedFlags(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now().UTC()
	st.PutFlag(model.Flag{ID: "kc-1", Rule: "keychain-access", Severity: 3, TS: now.Add(-time.Minute), PID: 200, Agent: "untagged:node"})

	hub := api.NewDeltaHub()
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)

	cfg, _ := config.Load("/nonexistent")
	procs := mapProcSource{1: {PID: 1, Comm: "launchd"}}
	tagger := agents.New(cfg, procs)
	tagger.SetOnTagged(reattributeUntaggedFlags(st, hub, time.Now))
	tagger.Refresh()

	procs[100] = agents.ProcInfo{PID: 100, PPID: 1, Exe: "/usr/local/bin/claude"}
	procs[200] = agents.ProcInfo{PID: 200, PPID: 100, Exe: "/usr/local/bin/node"}
	tagger.Refresh()

	if fl, _ := st.GetFlag("kc-1"); fl.Agent != "claude" {
		t.Fatalf("flag agent = %q, want claude", fl.Agent)
	}
	select {
	case d := <-sub:
		fl, ok := d.Data.(model.Flag)
		if d.Type != "flag" || !ok || fl.ID != "kc-1" || fl.Agent != "claude" {
			t.Fatalf("delta = %s %+v, want flag kc-1 for claude", d.Type, d.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("no flag delta after reattribution")
	}
}
