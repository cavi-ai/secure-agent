package correlate

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// An agent's write to the run record raises one finding; the same write by a
// process outside every agent family, and an agent's read, raise none.
func TestAgentWriteToStateDirectoryRaisesOneFinding(t *testing.T) {
	c := newTestCorrelator(t)
	db := c.cfg.DBPath
	record := db + ".run-record.json"
	base := time.Unix(1_700_000_000, 0)

	if f := c.Observe(event.Event{Kind: event.KindFileWrite, PID: 999, TS: base, Path: record}); len(f) != 0 {
		t.Fatalf("write outside an agent family raised %+v", f)
	}
	if f := c.Observe(event.Event{Kind: event.KindFileOpen, PID: 200, TS: base, Path: record, OpenFlags: event.OpenRead}); len(f) != 0 {
		t.Fatalf("agent read raised %+v", f)
	}

	flags := c.Observe(event.Event{Kind: event.KindFileWrite, PID: 200, TS: base.Add(time.Second), Path: record})
	if len(flags) != 1 || flags[0].Rule != "monitor-state-write" || flags[0].Severity != 3 {
		t.Fatalf("agent write raised %+v, want one monitor-state-write at severity 3", flags)
	}
	if text := flags[0].Evidence[0].Text; !strings.Contains(text, record) {
		t.Fatalf("finding text %q does not name %s", text, record)
	}
	if f := c.Observe(event.Event{Kind: event.KindFileWrite, PID: 200, TS: base.Add(2 * time.Second), Path: record}); len(f) != 0 {
		t.Fatalf("repeat write to the same path raised %+v", f)
	}

	for _, e := range []event.Event{
		{Kind: event.KindFileDelete, PID: 200, TS: base.Add(3 * time.Second), Path: db},
		{Kind: event.KindFileOpen, PID: 200, TS: base.Add(4 * time.Second), Path: filepath.Join(filepath.Dir(db), "spool-position.json"), OpenFlags: event.OpenWrite},
	} {
		if f := c.Observe(e); len(f) != 1 || f[0].Rule != "monitor-state-write" {
			t.Fatalf("%s of %s raised %+v, want one monitor-state-write", e.Kind, e.Path, f)
		}
	}

	// The hooks run inside agent process trees and write these two entries.
	for _, p := range []string{"activity.jsonl", "sessions_seen/abc"} {
		e := event.Event{Kind: event.KindFileOpen, PID: 200, TS: base.Add(6 * time.Second), Path: filepath.Join(filepath.Dir(db), p), OpenFlags: event.OpenWrite}
		if f := c.Observe(e); len(f) != 0 {
			t.Fatalf("hook-written %s raised %+v", p, f)
		}
	}

	sibling := filepath.Dir(db) + "-other/file"
	if f := c.Observe(event.Event{Kind: event.KindFileWrite, PID: 200, TS: base.Add(5 * time.Second), Path: sibling}); len(f) != 0 {
		t.Fatalf("write outside the state directory raised %+v", f)
	}
}

func TestStateWriteFromCompactedRename(t *testing.T) {
	for _, tc := range []struct {
		name, source, dest string
		want               []string
	}{
		{"out of state", "/state/events.db", "/other/events.db", []string{"/state/events.db"}},
		{"into state", "/other/replacement", "/state/events.db", []string{"/state/events.db"}},
		{"within state", "/state/old", "/state/new", []string{"/state/new", "/state/old"}},
		{"hook rotation", "/state/sessions_seen/old", "/state/sessions_seen/new", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCorrelator(t)
			cfg := c.cfg
			cfg.DBPath = "/state/events.db"
			c = New(c.tagger, c.classifier, cfg, Hooks{})
			line := fmt.Appendf(nil, `{"process":{"audit_token":{"pid":200}},"event":{"rename":{
				"source":{"path":%q},"destination":{"existing_file":{"path":%q}}}}}`, tc.source, tc.dest)
			// The collector keeps this compacted form in the spool.
			compact, ok := collect.CompactESLine(nil, line)
			if !ok {
				t.Fatal("could not compact rename record")
			}
			e, ok := collect.ParseESLine(compact)
			if !ok || e.Kind != event.KindFileWrite || e.Path != tc.dest {
				t.Fatalf("rename parsed to %+v, want destination %s", e, tc.dest)
			}
			var paths []string
			for _, flag := range c.Observe(e) {
				if flag.Rule == stateWriteRule {
					paths = append(paths, flag.Evidence[0].Label)
				}
			}
			if !slices.Equal(paths, tc.want) {
				t.Fatalf("monitor-state-write paths = %v, want %v", paths, tc.want)
			}
		})
	}
}

func TestStateWriteWithRelativeDBPath(t *testing.T) {
	c := newTestCorrelator(t)
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.cfg
	cfg.DBPath = "state/events.db"
	c = New(c.tagger, c.classifier, cfg, Hooks{})
	path := filepath.Join(cwd, "state", "events.db")
	flags := c.Observe(event.Event{Kind: event.KindFileWrite, PID: 200, TS: time.Now(), Path: path})
	if len(flags) != 1 || flags[0].Rule != stateWriteRule || flags[0].Evidence[0].Label != path {
		t.Fatalf("flags = %+v, want monitor-state-write for %s", flags, path)
	}
}
