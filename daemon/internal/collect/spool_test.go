package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// drainSpool runs a tailer against a test spool until want events arrive or
// the timeout fires; returns what it collected.
func drainSpool(t *testing.T, lines []string, want int, timeout time.Duration) []event.Event {
	t.Helper()
	path := t.TempDir() + "/spool.jsonl"
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	// Subscribe before the tailer starts: the bus delivers only to current
	// subscribers, so a tailer that drains first would publish into nothing.
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = tailer.Run(ctx) }()
	var got []event.Event
	deadline := time.After(timeout)
	for {
		select {
		case e := <-sub:
			got = append(got, e)
			if len(got) >= want {
				return got
			}
		case <-deadline:
			return got
		}
	}
}

func TestParseLaunchctlStateTakesFirstTopLevelState(t *testing.T) {
	// launchctl print output carries the service state at one tab of
	// indentation; nested sections (endpoints, mach services) repeat the
	// key at deeper indentation. A crash-looping service reads as
	// "spawn scheduled" only when the FIRST top-level state wins.
	out := "system/com.cavi-ai.secure-agent-esd = {\n" +
		"\tactive count = 1\n" +
		"\tpath = /Library/LaunchDaemons/com.cavi-ai.secure-agent-esd.plist\n" +
		"\tstate = spawn scheduled\n" +
		"\n" +
		"\tprogram = /Library/PrivilegedHelperTools/com.cavi-ai.secure-agent-esd\n" +
		"\tlast exit code = 1\n" +
		"\tmach services = {\n" +
		"\t\tcom.example = {\n" +
		"\t\t\tstate = running\n" +
		"\t\t}\n" +
		"\t}\n" +
		"}\n"
	if got := parseLaunchctlState(out); got != "spawn scheduled (last exit 1)" {
		t.Fatalf("state = %q, want spawn scheduled (last exit 1)", got)
	}
	// Clean exit: no annotation.
	clean := "\tstate = running\n\tlast exit code = 0\n"
	if got := parseLaunchctlState(clean); got != "running" {
		t.Fatalf("state = %q, want running", got)
	}
}

func TestParseLaunchctlProgramTakesTopLevelAbsolutePath(t *testing.T) {
	out := "system/com.cavi-ai.secure-agent-esd = {\n" +
		"\tactive count = 1\n" +
		"\tstate = running\n" +
		"\tprogram = /Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd\n" +
		"\tendpoints = {\n" +
		"\t\tprogram = /usr/libexec/other\n" +
		"\t}\n" +
		"}\n"
	if got := parseLaunchctlProgram(out); got != "/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd" {
		t.Fatalf("program = %q", got)
	}
	nested := "\tstate = running\n\tendpoints = {\n\t\tprogram = /usr/libexec/other\n\t}\n"
	if got := parseLaunchctlProgram(nested); got != "" {
		t.Fatalf("nested-only program = %q, want empty", got)
	}
	if got := parseLaunchctlProgram("\tprogram = relative/path\n"); got != "" {
		t.Fatalf("relative program = %q, want empty", got)
	}
}

func TestHelperMtimeStatsTheLaunchctlProgram(t *testing.T) {
	helper := t.TempDir() + "/secure-agent-esd"
	if err := os.WriteFile(helper, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(helper, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	out := "system/com.cavi-ai.secure-agent-esd = {\n\tstate = running\n\tprogram = " + helper + "\n}\n"
	if got := helperMtime(out); !got.Equal(stamp) {
		t.Fatalf("helperMtime = %v, want %v", got, stamp)
	}
	if got := helperMtime("\tstate = running\n"); !got.IsZero() {
		t.Fatalf("no program line: helperMtime = %v, want zero", got)
	}
	if got := helperMtime("\tprogram = " + helper + ".missing\n"); !got.IsZero() {
		t.Fatalf("missing program file: helperMtime = %v, want zero", got)
	}
}

func TestSpoolTailerParsesAndPublishes(t *testing.T) {
	// An ES open-event envelope exactly like eslogger emits.
	line := `{"event_type":0,"process":{"audit_token":{"pid":4242},"pid":4242,"executable":{"path":"/usr/bin/cat"}},"event":{"open":{"file":{"path":"/Users/x/.ssh/id_ed25519"}}},"time":"2026-09-11T12:00:00.000000Z"}`
	got := drainSpool(t, []string{line}, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Kind != 0 || got[0].PID != 4242 || got[0].Path != "/Users/x/.ssh/id_ed25519" {
		t.Fatalf("wrong event decoded: %+v", got[0])
	}
}

func TestSpoolTailerHandlesRotationAndGarbage(t *testing.T) {
	// Malformed lines must not kill the tail; partial lines across reads are
	// handled by the line-scanner (no event, no crash).
	line := `{"event_type":0,"process":{"audit_token":{"pid":7},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}`
	got := drainSpool(t, []string{"not json", "{broken", line, ""}, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event amid garbage, got %d", len(got))
	}
	if got[0].PID != 7 {
		t.Fatalf("wrong pid: %+v", got[0])
	}
}

// An unchanged spool is not opened: the tick costs one stat. A spool whose
// size or mtime moved is drained, and a rotated spool is re-read from 0.
func TestSpoolPollSkipsUnchangedSpool(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	line := func(pid int) string {
		return fmt.Sprintf(`{"event_type":0,"process":{"audit_token":{"pid":%d},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}`+"\n", pid)
	}
	if err := os.WriteFile(path, []byte(line(1)), 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	opens := 0
	tailer.open = func(p string) (*os.File, error) {
		opens++
		return os.Open(p)
	}
	expect := func(pid int32) {
		t.Helper()
		select {
		case e := <-sub:
			if e.PID != pid {
				t.Fatalf("drained pid %d, want %d", e.PID, pid)
			}
		default:
			t.Fatalf("no event drained, want pid %d", pid)
		}
	}

	var c spoolCursor
	c = tailer.poll(c)
	expect(1)
	for i := 0; i < 5; i++ {
		c = tailer.poll(c)
	}
	if opens != 1 {
		t.Fatalf("spool opened %d times across 5 unchanged ticks; want 1 (the first drain)", opens)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line(2)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	c = tailer.poll(c)
	expect(2)
	if opens != 2 {
		t.Fatalf("changed spool: %d opens, want 2", opens)
	}

	// Rotation: a shorter new file resets the offset, then is read from 0.
	if err := os.WriteFile(path, []byte(line(3)), 0o640); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	for i := 0; i < 3; i++ {
		c = tailer.poll(c)
	}
	expect(3)
}

// A flooding spool (a defective writer's near-empty garbage lines, far past
// the per-tick drain budget) is drained past the budget and the rest of the
// tail skipped in one tick — not scanned line by line — and reported via
// Stats(). A following tick with real lines drains normally and clears the
// flood signal.
func TestSpoolTailerSkipsFloodPastBudget(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	body := bytes.Repeat([]byte("ab\n"), (10<<20)/3) // ~10 MiB of 2-byte lines
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(128) // capacity for the 100 valid recovery events
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)

	c := tailer.poll(spoolCursor{})
	if c.offset != int64(len(body)) {
		t.Fatalf("offset after flood tick = %d, want EOF %d", c.offset, len(body))
	}
	stats := tailer.Stats()
	if stats.BytesSkipped == 0 {
		t.Fatal("BytesSkipped = 0 after a tick well past the drain budget, want > 0")
	}
	if stats.FloodSince.IsZero() {
		t.Fatal("FloodSince not set after a flooding tick")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"event_type":0,"process":{"audit_token":{"pid":9},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}` + "\n"
	for i := 0; i < 100; i++ {
		if _, err := f.WriteString(valid); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	c = tailer.poll(c)
	if c.offset != int64(len(body))+int64(len(valid))*100 {
		t.Fatalf("offset after clean tick = %d, want end of the appended lines", c.offset)
	}
	stats = tailer.Stats()
	if stats.Parsed != 100 {
		t.Fatalf("Parsed = %d, want 100 — the valid lines must still be drained after a flood", stats.Parsed)
	}
	if !stats.FloodSince.IsZero() {
		t.Fatal("FloodSince not cleared after a tick that drained fully within budget")
	}
	select {
	case e := <-sub:
		if e.PID != 9 {
			t.Fatalf("published event pid = %d, want 9", e.PID)
		}
	default:
		t.Fatal("no parsed event published after the flood cleared")
	}
}

// A burst of valid lines exceeding the byte budget must stay on disk for
// later polls, rather than being skipped or mistaken for garbage.
func TestSpoolTailerBudgetHitOverValidLinesCountsOnlyReadLines(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	valid := `{"event_type":0,"process":{"audit_token":{"pid":9},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}` + "\n"
	n := (8<<20)/len(valid) + 1000 // > 8 MiB of valid lines, well past the 4 MiB budget
	body := bytes.Repeat([]byte(valid), n)
	if err := os.WriteFile(path, body, 0o640); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	tailer := NewSpoolTailerAt(b, path)

	c := tailer.poll(spoolCursor{})
	stats := tailer.Stats()
	if c.offset <= 0 || c.offset >= int64(len(body)) || stats.Skipped != 0 || stats.BytesLost != 0 {
		t.Fatalf("valid backlog was skipped: offset=%d size=%d stats=%+v", c.offset, len(body), stats)
	}
	if stats.Lines != stats.Parsed {
		t.Fatalf("Lines = %d, Parsed = %d, want equal", stats.Lines, stats.Parsed)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(10)+"\n")
	current, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for tick := 0; !os.SameFile(c.file, current); tick++ {
		if tick > 10 {
			t.Fatal("rotated backlog did not finish")
		}
		previous := c.offset
		previousFile := c.file
		c = tailer.poll(c)
		if os.SameFile(previousFile, c.file) && c.offset <= previous {
			t.Fatal("valid backlog did not resume")
		}
	}
	if c.offset != current.Size() {
		t.Fatal("new spool was not drained after retained backlog")
	}
	if tailer.Stats().BytesLost != 0 {
		t.Fatal("valid burst lost evidence")
	}
}

// flooding_since is absent from the wire while the tailer is not skipping,
// and carries the skip start once it is.
func TestESServiceSnapshotFloodingSinceOmittedWhenUnset(t *testing.T) {
	quiet, err := json.Marshal(ESServiceSnapshot{State: "running"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(quiet, []byte("flooding_since")) {
		t.Fatalf("unset flooding_since serialized: %s", quiet)
	}
	since := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	busy, err := json.Marshal(ESServiceSnapshot{State: "running", Flooding: true, FloodingSince: &since})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(busy, []byte(`"flooding_since":"2026-09-25T12:00:00Z"`)) {
		t.Fatalf("flooding_since missing: %s", busy)
	}
}

// Rotation renames the spool to .1 before creating the new one. A probe in
// that gap must see the rotated file, not a missing collector.
func TestSpoolProbesSeeTheRotatedFileMidRotation(t *testing.T) {
	path := t.TempDir() + "/es-spool.jsonl"
	if size, mod := spoolFacts(path); size != 0 || !mod.IsZero() || spoolAvailableAt(path) {
		t.Fatalf("no spool: facts = %d %v, available = %v; want zero and false", size, mod, spoolAvailableAt(path))
	}

	if err := os.WriteFile(path+".1", []byte("rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if size, mod := spoolFacts(path); size != 8 || mod.IsZero() {
		t.Fatalf("mid-rotation facts = %d %v, want the .1 file's 8 bytes and mtime", size, mod)
	}
	if !spoolAvailableAt(path) {
		t.Fatal("mid-rotation: spool reported unavailable")
	}

	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if size, _ := spoolFacts(path); size != 4 {
		t.Fatalf("after rotation facts size = %d, want the new spool's 4 bytes", size)
	}
}

func esOpenLine(pid int) string {
	return fmt.Sprintf(`{"event_type":0,"process":{"audit_token":{"pid":%d},"executable":{"path":"/bin/ls"}},"event":{"open":{"file":{"path":"/etc/hosts"}}},"time":"2026-09-11T12:00:00Z"}`, pid)
}

func appendSpool(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func drainedPIDs(sub <-chan event.Event) []int32 {
	var pids []int32
	for {
		select {
		case e := <-sub:
			pids = append(pids, e.PID)
		default:
			return pids
		}
	}
}

// Rotation renames the spool to .1 and starts a new file. Lines appended to
// the old file after the last drain are read from .1, and the new spool is
// read from its start even when it has already grown past the old offset.
func TestSpoolTailerFinishesTheRotatedFile(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n")
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)

	c := tailer.poll(spoolCursor{})
	appendSpool(t, path, esOpenLine(2)+"\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	c = tailer.poll(c) // the rotation window: no spool yet
	appendSpool(t, path, esOpenLine(3)+"\n"+esOpenLine(4)+"\n"+esOpenLine(5)+"\n")
	tailer.poll(c)

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{1, 2, 3, 4, 5}) {
		t.Fatalf("drained pids = %v, want [1 2 3 4 5]: the old file's tail, then the new spool from its start", got)
	}
}

// A line the writer has not finished is left for the next drain, not taken
// as a line (garbage) with its rest read as garbage after it.
func TestSpoolTailerWaitsForTheRestOfALine(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	whole := esOpenLine(2)
	appendSpool(t, path, esOpenLine(1)+"\n"+whole[:40])
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)

	c := tailer.poll(spoolCursor{})
	if want := int64(len(esOpenLine(1)) + 1); c.offset != want {
		t.Fatalf("offset = %d, want %d (the end of the complete line)", c.offset, want)
	}
	if s := tailer.Stats(); s.Lines != 1 || s.Parsed != 1 {
		t.Fatalf("stats = %+v, want 1 line read and parsed", s)
	}
	appendSpool(t, path, whole[40:]+"\n")
	tailer.poll(c)
	if got := drainedPIDs(sub); !slices.Equal(got, []int32{1, 2}) {
		t.Fatalf("drained pids = %v, want [1 2]", got)
	}
}

// The daemon's own file activity is a valid line it drops on purpose, not
// garbage: a drain made of it must not read as a writer producing garbage.
func TestSpoolStatsCountTheDaemonsOwnEventsAsParsed(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	own := os.Getpid()
	appendSpool(t, path, esOpenLine(own)+"\n"+esOpenLine(own)+"\n"+esOpenLine(7)+"\n"+"not json\n")
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	tailer.poll(spoolCursor{})

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{7}) {
		t.Fatalf("published pids = %v, want [7]", got)
	}
	if s := tailer.Stats(); s.Lines != 4 || s.Parsed != 3 {
		t.Fatalf("stats = %+v, want 4 lines, 3 parsed (only the non-JSON line is garbage)", s)
	}
}

// The feed clock is the newest published event's own time, kept across
// drains; its lag is how far that trails the wall clock, reported only
// while fresh.
func TestSpoolTailerTracksFeedClockAndLag(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	wall := time.Date(2026, 10, 2, 21, 43, 0, 0, time.UTC)
	esLine := func(pid int, at time.Time) string {
		return fmt.Sprintf(`{"event_type":0,"process":{"audit_token":{"pid":%d},"pid":%d,"executable":{"path":"/usr/bin/cat"}},"event":{"open":{"file":{"path":"/tmp/x"}}},"time":%q}`, pid, pid, at.Format(time.RFC3339Nano))
	}
	behind := wall.Add(-2*time.Hour - 13*time.Minute)
	appendSpool(t, path, esLine(7, behind.Add(-time.Second))+"\n"+esLine(8, behind)+"\n")
	b := bus.New(64)
	_ = b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	tailer.now = func() time.Time { return wall }
	c := tailer.poll(spoolCursor{})

	s := tailer.Stats()
	if !s.NewestEvent.Equal(behind) || s.Lag != 2*time.Hour+13*time.Minute {
		t.Fatalf("stats = %+v, want newest %s lagging 2h13m", s, behind)
	}
	appendSpool(t, path, "not json\n")
	c = tailer.poll(c)
	if s := tailer.Stats(); !s.NewestEvent.Equal(behind) || s.Lag != 2*time.Hour+13*time.Minute {
		t.Fatalf("a drain with no event reset the feed clock: %+v", s)
	}
	appendSpool(t, path, esLine(9, wall.Add(-time.Second))+"\n")
	tailer.poll(c)
	if s := tailer.Stats(); !s.NewestEvent.Equal(wall.Add(-time.Second)) || s.Lag != time.Second {
		t.Fatalf("caught-up stats = %+v", s)
	}
	tailer.now = func() time.Time { return wall.Add(spoolLagFresh + time.Second) }
	if s := tailer.Stats(); s.Lag != 0 || s.NewestEvent.IsZero() {
		t.Fatalf("stale lag still reported: %+v", s)
	}
}

func TestSpoolRetainsRejectedLineAcrossPollsAndRotation(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n"+esOpenLine(3)+"\n")
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	c := tailer.poll(spoolCursor{})
	first := int64(len(esOpenLine(1)) + 1)
	if c.offset != first || b.Dropped() != 0 {
		t.Fatalf("offset=%d drops=%d; rejected line must stay unread", c.offset, b.Dropped())
	}
	// A second poll with no available slot must preserve that exact cursor.
	c = tailer.poll(c)
	if c.offset != first {
		t.Fatal("advanced past rejected event")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(4)+"\n")
	for _, want := range []int32{1, 2, 3, 4} {
		select {
		case got := <-sub:
			if got.PID != want {
				t.Fatalf("PID=%d want=%d", got.PID, want)
			}
		default:
			t.Fatalf("missing PID %d", want)
		}
		c = tailer.poll(c)
	}
	if len(sub) != 0 || b.Dropped() != 0 {
		t.Fatal("duplicates or delivery loss")
	}
}

func TestSpoolLossSurvivesHealthyPollAfterOverwrittenRotation(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n")
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	lossTime := time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC)
	tailer.now = func() time.Time { return lossTime }
	c := tailer.poll(spoolCursor{})
	if !tailer.Stats().LostAt.IsZero() {
		t.Fatal("LostAt set before any loss")
	}
	want := uint64(c.size - c.offset)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(3)+"\n")
	// A second rotation overwrites the retained tail before it can be read.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(4)+"\n")
	<-sub
	c = tailer.poll(c)
	if got := tailer.Stats().BytesLost; got != want || got == 0 {
		t.Fatalf("lost=%d want=%d", got, want)
	}
	if got := tailer.Stats().LostAt; !got.Equal(lossTime) {
		t.Fatalf("LostAt = %v, want the loss time %v", got, lossTime)
	}
	<-sub
	tailer.now = func() time.Time { return lossTime.Add(time.Hour) }
	tailer.poll(c)
	if tailer.Stats().BytesLost != want || !tailer.Stats().LostAt.Equal(lossTime) {
		t.Fatal("healthy tick erased historical loss or moved its time")
	}
}

func TestLossGrowingWithinTheWindow(t *testing.T) {
	now := time.Date(2026, 10, 8, 15, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{time.Time{}, false},
		{now.Add(-time.Minute), true},
		{now.Add(-LossWindow + time.Second), true},
		{now.Add(-LossWindow), false},
	} {
		if got := LossGrowing(c.at, now); got != c.want {
			t.Errorf("LossGrowing(%v) = %v, want %v", c.at, got, c.want)
		}
	}
}

func TestSpoolPendingEventReportsLagWithoutAdvancingFeed(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n")
	b := bus.New(1)
	defer b.Close()
	b.Subscribe()
	b.Publish(event.Event{})
	tailer := NewSpoolTailerAt(b, path)
	tailer.now = func() time.Time { return time.Date(2026, 9, 11, 12, 1, 0, 0, time.UTC) }
	tailer.poll(spoolCursor{})
	stats := tailer.Stats()
	if stats.Lag <= 0 || !stats.NewestEvent.IsZero() {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestSpoolRotatedPartialLineDoesNotStallNewFile(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n"+"unfinished")
	b := bus.New(8)
	defer b.Close()
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	c := tailer.poll(spoolCursor{})
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(2)+"\n")
	tailer.poll(c)
	if got := drainedPIDs(sub); !slices.Equal(got, []int32{1, 2}) {
		t.Fatalf("PIDs=%v", got)
	}
	if got := tailer.Stats().BytesLost; got != uint64(len("unfinished")) {
		t.Fatalf("lost=%d", got)
	}
}

func TestSpoolTruncationRetainsNewContentAndReportsUnreadLoss(t *testing.T) {
	path := t.TempDir() + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n")
	b := bus.New(1)
	defer b.Close()
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	c := tailer.poll(spoolCursor{})
	want := uint64(c.size - c.offset)
	if err := os.WriteFile(path, []byte(esOpenLine(3)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	<-sub
	tailer.poll(c)
	if got := <-sub; got.PID != 3 {
		t.Fatalf("PID=%d", got.PID)
	}
	if got := tailer.Stats().BytesLost; got != want {
		t.Fatalf("lost=%d want=%d", got, want)
	}
}
