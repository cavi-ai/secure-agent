package collect

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestParseOpenLine(t *testing.T) {
	line := []byte(`{"process":{"audit_token":{"pid":1234}},"event":{"open":{"file":{"path":"/Users/x/proj/.env"}}}}`)
	e, ok := ParseESLine(line)
	if !ok || e.Kind != event.KindFileOpen {
		t.Fatalf("ParseESLine kind = %v, ok = %v; want KindFileOpen, true", e.Kind, ok)
	}
	if e.Path != "/Users/x/proj/.env" || e.PID != 1234 {
		t.Fatalf("missing or wrong path/pid: %+v", e)
	}
}

func TestParseOpenLineCarriesFlagsAndStat(t *testing.T) {
	line := []byte(`{"process":{"audit_token":{"pid":1234}},"event":{"open":{"fflag":16777218,"file":{"path":"/work/t/001/.env","stat":{"st_mode":33188,"st_ino":392390172,"st_dev":16777241,"st_birthtimespec":"2026-09-20T13:54:55.465626215Z"}}}}}`)
	e, ok := ParseESLine(line)
	if !ok {
		t.Fatal("line not parsed")
	}
	birth := time.Date(2026, 9, 20, 13, 54, 55, 465626215, time.UTC).UnixNano()
	if e.OpenFlags != 16777218 || !e.OpensForWrite() || e.OpensForRead() || e.FileMode != 33188 || e.IsDirOpen() || e.FileIno != 392390172 || e.FileBirth != birth {
		t.Fatalf("open facts = flags %d mode %o ino %d birth %d", e.OpenFlags, e.FileMode, e.FileIno, e.FileBirth)
	}
	dir := []byte(`{"process":{"audit_token":{"pid":1234}},"event":{"open":{"fflag":1,"file":{"path":"/work/.docker","stat":{"st_mode":16877}}}}}`)
	if e, _ := ParseESLine(dir); !e.IsDirOpen() || !e.OpensForRead() {
		t.Fatalf("directory open facts = %+v", e)
	}
	old := []byte(`{"process":{"audit_token":{"pid":1234}},"event":{"open":{"file":{"path":"/work/a"}}}}`)
	if e, _ := ParseESLine(old); e.OpenFlags != 0 || e.FileMode != 0 || e.FileIno != 0 || e.FileBirth != 0 || !e.OpensForRead() {
		t.Fatalf("line without stat = %+v", e)
	}
}

func TestParseESLineCarriesTheParentPid(t *testing.T) {
	line := []byte(`{"process":{"audit_token":{"pid":4242},"ppid":100,"executable":{"path":"/usr/bin/git"}},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/git"}}}}}`)
	e, ok := ParseESLine(line)
	if !ok || e.PID != 4242 || e.PPID != 100 {
		t.Fatalf("ParseESLine = %+v, %v; want pid 4242 ppid 100", e, ok)
	}
}

var (
	esFullStart    = time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	esFullLineTime = time.Date(2026, 11, 1, 3, 31, 59, 123456789, time.UTC)
)

func sameLineage(a, b agents.Lineage) bool {
	return a.ParentPID == b.ParentPID && a.ChildPID == b.ChildPID && a.ParentStart.Equal(b.ParentStart) &&
		a.ChildStart.Equal(b.ChildStart) && a.At.Equal(b.At)
}

// A fork record names the forking process and its child, full or compacted,
// and is never an event.
func TestParseESLineForkIsLineageOnly(t *testing.T) {
	line := []byte(esFullLines()["fork"])
	compact, ok := CompactESLine(nil, line)
	if !ok {
		t.Fatalf("fork line not compacted: %s", line)
	}
	want := agents.Lineage{ParentPID: 4242, ParentStart: esFullStart, ChildPID: 4243, ChildStart: esFullStart, At: esFullLineTime}
	for name, l := range map[string][]byte{"full": line, "compact": compact} {
		if e, ok := ParseESLine(l); ok {
			t.Fatalf("%s fork line parsed to event %+v", name, e)
		}
		if _, got, v := parseESLine(l); v != esLineage || !sameLineage(got, want) {
			t.Fatalf("%s fork line = %+v (%v), want %+v", name, got, v, want)
		}
	}
}

// An exec record is the same event as before and names the process's
// forking parent: original_ppid when above 1, else ppid.
func TestParseESLineExecCarriesLineage(t *testing.T) {
	line := esFullLines()["exec"]
	for _, c := range []struct {
		name, from, to   string
		ppid, wantParent int32
	}{
		{"same parent", "", "", 100, 100},
		{"adopted by launchd", `"ppid":100,"original_ppid":100`, `"ppid":1,"original_ppid":4100`, 1, 4100},
		{"no original_ppid", `,"original_ppid":100`, ``, 100, 100},
	} {
		l := line
		if c.from != "" {
			l = strings.Replace(line, c.from, c.to, 1)
		}
		want := event.Event{Kind: event.KindExec, TS: esFullLineTime, PID: 4242, PPID: c.ppid, ExePath: "/usr/local/bin/node", Path: "/usr/bin/git"}
		e, got, v := parseESLine([]byte(l))
		if v != esEvent || !reflect.DeepEqual(e, want) {
			t.Fatalf("%s: exec event = %+v (%v), want %+v", c.name, e, v, want)
		}
		if wantL := (agents.Lineage{ParentPID: c.wantParent, ChildPID: 4242, ChildStart: esFullStart, At: esFullLineTime}); !sameLineage(got, wantL) {
			t.Fatalf("%s: exec lineage = %+v, want %+v", c.name, got, wantL)
		}
	}
}

func TestParseESLineDropsOwnPid(t *testing.T) {
	line := func(pid int) []byte {
		return []byte(fmt.Sprintf(`{"process":{"audit_token":{"pid":%d}},"event":{"open":{"file":{"path":"/Users/x/proj/.env"}}}}`, pid))
	}
	if _, ok := ParseESLine(line(os.Getpid())); ok {
		t.Fatal("ParseESLine accepted an event from the daemon's own pid")
	}
	if _, ok := ParseESLine(line(os.Getpid() + 1)); !ok {
		t.Fatal("ParseESLine dropped an event from another pid")
	}
}

// countingUnmarshal swaps in for unmarshalES for the duration of the test
// and counts how many times ParseESLine actually reaches json.Unmarshal.
func countingUnmarshal(t *testing.T) *int {
	t.Helper()
	prev := unmarshalES
	calls := 0
	unmarshalES = func(data []byte, v any) error {
		calls++
		return prev(data, v)
	}
	t.Cleanup(func() { unmarshalES = prev })
	return &calls
}

func TestParseESLineFastRejectsShortLine(t *testing.T) {
	calls := countingUnmarshal(t)
	if _, ok := ParseESLine([]byte("xy")); ok {
		t.Fatal("2-byte line must not parse")
	}
	if _, ok := ParseESLine([]byte(`,"st_ino":1`)); ok {
		t.Fatal("fragment must not parse")
	}
	if *calls != 0 {
		t.Fatalf("fast-reject reached json.Unmarshal %d times for short/fragment lines, want 0", *calls)
	}
}

func TestParseESLineFastRejectsGarbageWithoutJSON(t *testing.T) {
	calls := countingUnmarshal(t)
	garbage := bytes.Repeat([]byte(","), 1<<20)
	start := time.Now()
	if _, ok := ParseESLine(garbage); ok {
		t.Fatal("1 MiB of commas must not parse")
	}
	if elapsed := time.Since(start); elapsed > time.Millisecond {
		t.Fatalf("fast-reject took %v for 1 MiB of garbage, want under 1ms", elapsed)
	}
	if *calls != 0 {
		t.Fatalf("fast-reject reached json.Unmarshal %d times for 1 MiB of garbage, want 0", *calls)
	}
}
