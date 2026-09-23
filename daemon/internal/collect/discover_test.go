package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// buildShapedTree writes 2,000 transcripts across the four harness shapes
// (500 each) under home, plus 20,000 decoy .jsonl files in a Cursor project
// tree outside agent-transcripts and agy duplicates beside the full
// transcripts. It returns the transcript paths the shapes must find and the
// number of directories in the tree.
func buildShapedTree(tb testing.TB, home string) (want []string, dirs int) {
	tb.Helper()
	madeDirs := map[string]bool{}
	put := func(p string, keep bool) {
		d := filepath.Dir(p)
		if !madeDirs[d] {
			if err := os.MkdirAll(d, 0o755); err != nil {
				tb.Fatal(err)
			}
			for ; d != home && !madeDirs[d]; d = filepath.Dir(d) {
				madeDirs[d] = true
			}
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			tb.Fatal(err)
		}
		if keep {
			want = append(want, p)
		}
	}
	claude := filepath.Join(home, ".claude", "projects")
	for p := 0; p < 10; p++ {
		proj := filepath.Join(claude, fmt.Sprintf("-repo-%d", p))
		for s := 0; s < 40; s++ {
			put(filepath.Join(proj, fmt.Sprintf("sess-%02d.jsonl", s)), true)
		}
		for s := 0; s < 2; s++ {
			for a := 0; a < 4; a++ {
				put(filepath.Join(proj, fmt.Sprintf("sess-%02d", s), "subagents", fmt.Sprintf("agent-%d.jsonl", a)), true)
			}
		}
	}
	for w := 0; w < 5; w++ {
		for a := 0; a < 4; a++ {
			put(filepath.Join(claude, "-repo-0", "sess-00", "subagents", "workflows", fmt.Sprintf("wf-%d", w), fmt.Sprintf("agent-%d.jsonl", a)), true)
		}
	}
	cursor := filepath.Join(home, ".cursor", "projects")
	for p := 0; p < 10; p++ {
		for s := 0; s < 5; s++ {
			sess := filepath.Join(cursor, fmt.Sprintf("repo-%d", p), "agent-transcripts", fmt.Sprintf("s-%d", s))
			for f := 0; f < 8; f++ {
				put(filepath.Join(sess, fmt.Sprintf("t-%d.jsonl", f)), true)
			}
			for f := 0; f < 2; f++ {
				put(filepath.Join(sess, "subagents", fmt.Sprintf("sub-%d.jsonl", f)), true)
			}
		}
	}
	for d := 0; d < 200; d++ {
		for f := 0; f < 100; f++ {
			put(filepath.Join(cursor, "decoy-repo", "worktree", fmt.Sprintf("d%03d", d), fmt.Sprintf("f%02d.jsonl", f)), false)
		}
	}
	for day := 1; day <= 10; day++ {
		for r := 0; r < 50; r++ {
			put(filepath.Join(home, ".codex", "sessions", "2026", "09", fmt.Sprintf("%02d", day), fmt.Sprintf("rollout-%02d.jsonl", r)), true)
		}
	}
	for br := 0; br < 500; br++ {
		logs := filepath.Join(home, ".gemini", "antigravity-cli", "brain", fmt.Sprintf("b-%03d", br), ".system_generated", "logs")
		put(filepath.Join(logs, "transcript_full.jsonl"), true)
		if br < 50 {
			put(filepath.Join(logs, "transcript.jsonl"), false)
			put(filepath.Join(logs, "chunks", "0", "0.jsonl"), false)
		}
	}
	sort.Strings(want)
	return want, len(madeDirs)
}

// Discovery by shape finds exactly the harness transcripts and lists only
// the directories on those shapes: the 20,000-file decoy tree beside the
// Cursor transcripts is never read.
func TestDiscoverShapedFindsOnlyShapedFiles(t *testing.T) {
	home := t.TempDir()
	want, treeDirs := buildShapedTree(t, home)
	if len(want) != 2000 {
		t.Fatalf("fixture has %d shaped files, want 2000", len(want))
	}
	reads := 0
	counting := func(d string) ([]os.DirEntry, error) {
		reads++
		return os.ReadDir(d)
	}
	var got []string
	for _, tgt := range HarnessTranscriptGlobs(home) {
		for _, f := range globFiles(tgt, counting) {
			got = append(got, f.path)
		}
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("discovered %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("discovered %q at %d, want %q", got[i], i, want[i])
		}
	}
	if reads >= 300 {
		t.Fatalf("discovery listed %d directories (tree holds %d); want < 300 — the decoy tree was walked", reads, treeDirs)
	}
	if treeDirs < 1000 {
		t.Fatalf("fixture has %d directories; the walk comparison needs a large tree", treeDirs)
	}
	t.Logf("shaped discovery listed %d of %d directories", reads, treeDirs)
}

// On shaped glob targets the seed and never-replay rules hold: a
// pre-existing transcript is seeded to EOF, one created after startup is
// read from byte 0, and an idle transcript that grows is read from its saved
// offset.
func TestShapedTargetsSeedNewAndIdleFiles(t *testing.T) {
	home := t.TempDir()
	idle := filepath.Join(home, ".claude", "projects", "-repo", "idle.jsonl")
	if err := os.MkdirAll(filepath.Dir(idle), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idle, []byte(`{"tool":"Old"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, HarnessTranscriptGlobs(home))
	ts.tailEvery = 10 * time.Millisecond
	ts.resolveEvery = 30 * time.Millisecond
	ts.activeWindowD = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ts.Run(ctx)
	time.Sleep(100 * time.Millisecond)

	// Age the seeded file out of the active set, then let a resolve pass drop it.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(idle, old, old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	fresh := filepath.Join(home, ".cursor", "projects", "repo", "agent-transcripts", "s-1", "new.jsonl")
	if err := os.MkdirAll(filepath.Dir(fresh), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fresh, []byte(`{"tool":"New"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(idle, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"tool":"Grown"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for !seen["New"] || !seen["Grown"] {
		select {
		case e := <-sub:
			if e.Kind != event.KindPluginAction {
				continue
			}
			if e.Detail == "Old" {
				t.Fatal("pre-existing transcript content was replayed")
			}
			seen[e.Detail] = true
		case <-deadline:
			t.Fatalf("saw %v; want the new file read from byte 0 and the idle file's appended line", seen)
		}
	}
}

func persistedOffset(t *testing.T, statePath, p string) (int64, bool) {
	t.Helper()
	data, err := os.ReadFile(statePath)
	if err != nil {
		return 0, false
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("offset file: %v", err)
	}
	off, ok := m[p]
	return off, ok
}

// Ten dirty tail ticks inside the save interval write the offset file once;
// shutdown writes the final offsets.
func TestOffsetSavesCoalesce(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "activity.jsonl")
	statePath := filepath.Join(dir, "offsets.json")
	if err := os.WriteFile(logPath, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	b := bus.New(64)
	sub := b.Subscribe()
	ts := NewTranscriptScanner(b, []string{logPath})
	ts.OffsetStatePath = statePath
	ts.tailEvery = 10 * time.Millisecond
	ts.resolveEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = ts.Run(ctx); close(done) }()
	defer func() {
		cancel()
		<-done
	}()

	// The startup seed is the one write inside the interval.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if off, ok := persistedOffset(t, statePath, logPath); ok && off == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("startup seed was never persisted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	for i := 0; i < 10; i++ {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(f, `{"tool":"T%d"}`+"\n", i); err != nil {
			t.Fatal(err)
		}
		f.Close()
		select {
		case <-sub:
		case <-time.After(3 * time.Second):
			t.Fatalf("append %d was not tailed", i)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if off, _ := persistedOffset(t, statePath, logPath); off != 5 {
		t.Fatalf("persisted offset %d after 10 dirty ticks; want 5 (one write per save interval)", off)
	}

	cancel()
	<-done
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if off, _ := persistedOffset(t, statePath, logPath); off != fi.Size() {
		t.Fatalf("persisted offset %d after shutdown; want %d", off, fi.Size())
	}
}

func BenchmarkDiscoverShaped(b *testing.B) {
	home := b.TempDir()
	want, _ := buildShapedTree(b, home)
	targets := HarnessTranscriptGlobs(home)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for _, tgt := range targets {
			n += len(globFiles(tgt, os.ReadDir))
		}
		if n != len(want) {
			b.Fatalf("found %d files, want %d", n, len(want))
		}
		b.ReportMetric(float64(n), "files")
	}
}

func BenchmarkDiscoverWalk(b *testing.B) {
	home := b.TempDir()
	buildShapedTree(b, home)
	roots := []string{
		filepath.Join(home, ".claude", "projects"),
		filepath.Join(home, ".cursor", "projects"),
		filepath.Join(home, ".codex", "sessions"),
		filepath.Join(home, ".gemini", "antigravity-cli", "brain"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		for _, r := range roots {
			n += len(walkDir(r))
		}
		b.ReportMetric(float64(n), "files")
	}
}
