package agents

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type fakeProcs map[int32]ProcInfo

func (f fakeProcs) List() []ProcInfo {
	res := make([]ProcInfo, 0, len(f))
	for _, p := range f {
		res = append(res, p)
	}
	return res
}

func (f fakeProcs) Info(pid int32) (ProcInfo, bool) {
	p, ok := f[pid]
	return p, ok
}

func TestTagInheritsFromAgentParent(t *testing.T) {
	fake := fakeProcs{
		100: {PID: 100, PPID: 1, Exe: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper"},
		200: {PID: 200, PPID: 100, Exe: "/usr/local/bin/node"},
		999: {PID: 999, PPID: 1, Exe: "/bin/ls"},
	}
	c, _ := config.Load("/nonexistent")
	tg := New(c, fake)
	tg.Refresh()
	info, ok := tg.Tag(200)
	if !ok || info.Name != "cursor" {
		t.Fatalf("Tag(200) = %+v, %v; want cursor,true", info, ok)
	}
	if _, ok := tg.Tag(999); ok {
		t.Fatal("Tag(999) tagged an unrelated process")
	}
	if !tg.Any() {
		t.Fatal("Any() = false with a live agent")
	}
}
