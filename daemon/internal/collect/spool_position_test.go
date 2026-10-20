package collect

import (
	"os"
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
)

// A run without a saved position starts at the spool's last line: the lines
// before it are neither read nor counted lost.
func TestSpoolTailerWithoutSavedPositionStartsAtTheEnd(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/spool.jsonl"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n")
	b := bus.New(64)
	sub := b.Subscribe()
	tailer := NewSpoolTailerAt(b, path)
	tailer.StatePath = dir + "/position.json"

	c := tailer.poll(tailer.startCursor())
	appendSpool(t, path, esOpenLine(3)+"\n")
	tailer.poll(c)

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{3}) {
		t.Fatalf("drained pids = %v, want [3]: only lines written after the run started", got)
	}
	if lost := tailer.Stats().BytesLost; lost != 0 {
		t.Fatalf("%d bytes counted lost, want 0", lost)
	}
}

// A restart resumes the saved position: lines the last run read are not
// read again, and lines written while the daemon was down are.
func TestSpoolTailerResumesTheSavedPosition(t *testing.T) {
	dir := t.TempDir()
	path, position := dir+"/spool.jsonl", dir+"/position.json"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n")
	b := bus.New(64)
	sub := b.Subscribe()
	first := NewSpoolTailerAt(b, path)
	first.StatePath = position
	first.savePosition(first.poll(spoolCursor{}), true)

	appendSpool(t, path, esOpenLine(3)+"\n")
	second := NewSpoolTailerAt(b, path)
	second.StatePath = position
	second.poll(second.startCursor())

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{1, 2, 3}) {
		t.Fatalf("drained pids = %v, want [1 2 3]: each line once across the restart", got)
	}
}

// A position saved in a spool that rotated while the daemon was down resumes
// in the rotated file, then reads the new spool from its start.
func TestSpoolTailerResumesInTheRotatedFile(t *testing.T) {
	dir := t.TempDir()
	path, position := dir+"/spool.jsonl", dir+"/position.json"
	appendSpool(t, path, esOpenLine(1)+"\n")
	b := bus.New(64)
	sub := b.Subscribe()
	first := NewSpoolTailerAt(b, path)
	first.StatePath = position
	first.savePosition(first.poll(spoolCursor{}), true)

	appendSpool(t, path, esOpenLine(2)+"\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(3)+"\n")
	second := NewSpoolTailerAt(b, path)
	second.StatePath = position
	second.poll(second.startCursor())

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{1, 2, 3}) {
		t.Fatalf("drained pids = %v, want [1 2 3]: the rotated file's tail, then the new spool", got)
	}
	if lost := second.Stats().BytesLost; lost != 0 {
		t.Fatalf("%d bytes counted lost, want 0", lost)
	}
}

// A saved position whose file rotated out entirely does not resume in a
// different file: the run starts at the spool's end.
func TestSpoolTailerIgnoresAPositionWhoseFileIsGone(t *testing.T) {
	dir := t.TempDir()
	path, position := dir+"/spool.jsonl", dir+"/position.json"
	appendSpool(t, path, esOpenLine(1)+"\n"+esOpenLine(2)+"\n")
	b := bus.New(64)
	sub := b.Subscribe()
	first := NewSpoolTailerAt(b, path)
	first.StatePath = position
	first.savePosition(first.poll(spoolCursor{}), true)
	drainedPIDs(sub)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	appendSpool(t, path, esOpenLine(7)+"\n"+esOpenLine(8)+"\n"+esOpenLine(9)+"\n")
	second := NewSpoolTailerAt(b, path)
	second.StatePath = position
	c := second.poll(second.startCursor())
	appendSpool(t, path, esOpenLine(10)+"\n")
	second.poll(c)

	if got := drainedPIDs(sub); !slices.Equal(got, []int32{10}) {
		t.Fatalf("drained pids = %v, want [10]: a stale position starts the run at the end", got)
	}
}
