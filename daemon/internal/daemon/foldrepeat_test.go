package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// A folded repeat is stored on the flag and pushed to the console as the
// updated flag; a repeat for a flag the store no longer holds pushes nothing.
func TestFoldFlagRepeatStoresAndPublishes(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hub := api.NewDeltaHub()
	deltas := hub.Subscribe()
	now := time.Now().UTC()
	st.PutFlag(model.Flag{ID: "f1", Rule: "sensitive-read-then-connect", Severity: 3, TS: now, Agent: "claude"})

	fold := foldFlagRepeat(st, hub)
	fold("gone", now)
	fold("f1", now.Add(time.Minute))

	if f, _ := st.GetFlag("f1"); f.Repeats != 1 {
		t.Fatalf("repeats = %d, want 1", f.Repeats)
	}
	select {
	case d := <-deltas:
		fl, ok := d.Data.(model.Flag)
		if d.Type != "flag" || !ok || fl.ID != "f1" || fl.Repeats != 1 {
			t.Fatalf("delta = %+v, want the f1 flag with 1 repeat", d)
		}
	case <-time.After(time.Second):
		t.Fatal("no flag delta")
	}
	select {
	case d := <-deltas:
		t.Fatalf("extra delta %+v", d)
	default:
	}
}
