//go:build darwin

package agents

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcArgvStopsBeforeEnvironment(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 3)
	buf = append(buf, []byte("/opt/.openclaw/node/bin/node\x00\x00\x00node\x00./mcp/server.mjs\x00[REDACTED]\x00\x00OPENCLAW_HOME=[REDACTED]\x00")...)
	args := procArgv(buf)
	if !reflect.DeepEqual(args, []string{"node", "./mcp/server.mjs", "[REDACTED]"}) {
		t.Fatal("argument parsing included unexpected fields")
	}
	if got := nodeProgram(args, "/plugins/provider"); got != "/plugins/provider/mcp/server.mjs" {
		t.Fatalf("program=%q", got)
	}
	for _, invalid := range [][]byte{nil, {0, 0, 0, 0}, {255, 255, 255, 255}, {100, 0, 0, 0, 0}, {1, 0, 0, 0, 'x'}} {
		if procArgv(invalid) != nil {
			t.Error("accepted malformed argument buffer")
		}
	}
}

func TestProcEnvVarReadsChild(t *testing.T) {
	// KERN_PROCARGS2 reports the environment AT EXEC, and macOS redacts it
	// for platform binaries (/bin/sleep shows nothing even to ps eww), so the
	// child is this test binary re-executed as a blocking helper.
	cmd := exec.Command(os.Args[0], "-test.run=TestEnvHelperProcess")
	cmd.Env = append(os.Environ(),
		"SECURE_AGENT_TEST_ENVVAR=probe-value-123",
		"GO_WANT_HELPER_PROCESS=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := ProcEnvVar(int32(cmd.Process.Pid), "SECURE_AGENT_TEST_ENVVAR"); got == "probe-value-123" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ProcEnvVar(child) never returned the exec-time env var")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := ProcEnvVar(int32(cmd.Process.Pid), "SECURE_AGENT_TEST_MISSING"); got != "" {
		t.Fatalf("missing var = %q, want empty", got)
	}
}

// TestEnvHelperProcess blocks forever when re-executed by
// TestProcEnvVarReadsChild; run directly it is a no-op pass.
func TestEnvHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	select {}
}

func TestSelfStartTimeAndRSS(t *testing.T) {
	src := NewDarwinProcSource()
	info, ok := src.Info(int32(os.Getpid()))
	if !ok {
		t.Fatal("Info(self) failed")
	}
	if info.StartTime.IsZero() {
		t.Fatal("StartTime is zero")
	}
	if info.StartTime.After(time.Now().Add(time.Minute)) {
		t.Fatalf("StartTime in the future: %v", info.StartTime)
	}
	if info.RSSBytes == 0 {
		t.Log("RSSBytes is 0 (proc_info may be restricted); start time still required")
	}
	if info.CWD == "" {
		t.Fatal("CWD is empty")
	}
	if !filepath.IsAbs(info.CWD) {
		t.Fatalf("CWD is not absolute: %q", info.CWD)
	}
}

func TestDarwinSourceReportsProcessGroup(t *testing.T) {
	self, want := int32(os.Getpid()), int32(unix.Getpgrp())
	if want == 0 {
		t.Fatal("getpgrp returned 0")
	}
	src := NewDarwinProcSource()
	info, ok := src.Info(self)
	if !ok || info.PGID != want {
		t.Fatalf("Info(self).PGID = %d (ok=%v), want %d", info.PGID, ok, want)
	}
	for _, p := range src.List() {
		if p.PID == self {
			if p.PGID != want {
				t.Fatalf("List entry for self: PGID = %d, want %d", p.PGID, want)
			}
			return
		}
	}
	t.Fatal("List has no entry for this process")
}

func TestDarwinArgv0ReadsOwnArgv0(t *testing.T) {
	got := (&DarwinProcSource{}).Argv0(int32(os.Getpid()))
	if got != os.Args[0] {
		t.Fatalf("Argv0(self) = %q, want %q", got, os.Args[0])
	}
	if (&DarwinProcSource{}).Argv0(-1) != "" {
		t.Fatal("Argv0 of an invalid pid must be empty")
	}
}
