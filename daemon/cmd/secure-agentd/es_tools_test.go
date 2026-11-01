package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const esTestDaemonExe = "/Applications/Secure Agent.app/Contents/Helpers/secure-agentd"

// esProc is a process object with its audit token and its parent's.
func esProc(pid, version, ppid, pversion int, exe string) string {
	return fmt.Sprintf(`{"audit_token":{"asid":1,"pid":%d,"pidversion":%d,"ruid":501},"ppid":%d,"executable":{"path":%q},"parent_audit_token":{"pid":%d,"pidversion":%d}}`,
		pid, version, ppid, exe, ppid, pversion)
}

func esExecLine(proc string, pid, version int, exe string) string {
	return `{"process":` + proc + fmt.Sprintf(`,"event":{"exec":{"target":{"audit_token":{"pid":%d,"pidversion":%d},"executable":{"path":%q}},"args":["x"]}},"time":"2026-11-01T00:00:00Z","event_type":9}`, pid, version, exe)
}

func esOpenBy(proc, path string) string {
	return `{"process":` + proc + `,"event":{"open":{"fflag":1,"file":{"path":"` + path + `"}}},"time":"2026-11-01T00:00:00Z","event_type":10}`
}

func useESTools(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	prevTools, prevNow, prevExe, prevEsc := esTools, esNow, esDaemonExe, esDaemonExeEscaped
	esTools, esNow = newESToolTracker(), func() time.Time { return now }
	setESDaemonExe(esTestDaemonExe)
	t.Cleanup(func() { esTools, esNow, esDaemonExe, esDaemonExeEscaped = prevTools, prevNow, prevExe, prevEsc })
	return &now
}

// The daemon's git (shim, then developer-tools git, then a git child) drops
// its opens; a sensitive-path open by it is kept.
func TestDaemonToolOpensAreDropped(t *testing.T) {
	useESTools(t)
	daemon := esProc(50, 5, 1, 1, esTestDaemonExe)
	for _, line := range []string{
		esExecLine(esProc(100, 6, 50, 5, esTestDaemonExe), 100, 7, "/usr/bin/git"),
		esExecLine(esProc(100, 7, 50, 5, "/usr/bin/git"), 100, 8, "/Library/Developer/CommandLineTools/usr/bin/git"),
		esExecLine(esProc(101, 9, 100, 8, "/Library/Developer/CommandLineTools/usr/bin/git"), 101, 10, "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http"),
	} {
		if !keepESLine([]byte(line)) {
			t.Fatalf("an exec was dropped: %s", line)
		}
	}
	for _, tool := range []string{esProc(100, 8, 50, 5, "/Library/Developer/CommandLineTools/usr/bin/git"), esProc(101, 10, 100, 8, "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http")} {
		if keepESLine([]byte(esOpenBy(tool, "/Users/dev/repo/src/main.go"))) {
			t.Fatalf("the daemon's git kept a worktree open: %s", tool)
		}
		escaped := strings.ReplaceAll(esOpenBy(tool, "/Users/dev/repo/src/main.go"), "/", `\/`)
		if keepESLine([]byte(escaped)) {
			t.Fatalf("the daemon's git kept an escaped worktree open: %s", escaped)
		}
		if !keepESLine([]byte(esOpenBy(tool, "/Users/dev/.aws/credentials"))) {
			t.Fatal("the daemon's git dropped a sensitive open")
		}
	}
	if !keepESLine([]byte(esOpenBy(daemon, "/Users/dev/.ssh/id_ed25519"))) {
		t.Fatal("the daemon dropped a sensitive open")
	}
}

// Agents the daemon starts, tools found elsewhere on PATH, programs a tool
// starts, tools started by other processes and tokens without a pidversion
// keep every open.
func TestOtherProcessesKeepTheirOpens(t *testing.T) {
	now := useESTools(t)
	git := esProc(100, 8, 50, 5, "/Library/Developer/CommandLineTools/usr/bin/git")
	esTools.noteExec([]byte(esExecLine(esProc(100, 6, 50, 5, esTestDaemonExe), 100, 8, "/Library/Developer/CommandLineTools/usr/bin/git")), []byte(`{"process":`+esProc(100, 6, 50, 5, esTestDaemonExe)))
	cases := []struct {
		name, exec string
		proc       string
	}{
		{"agent the daemon starts", esExecLine(esProc(200, 1, 50, 5, esTestDaemonExe), 200, 2, "/usr/local/bin/claude"), esProc(200, 2, 50, 5, "/usr/local/bin/claude")},
		{"git found elsewhere on PATH", esExecLine(esProc(201, 1, 50, 5, esTestDaemonExe), 201, 2, "/Users/dev/bin/git"), esProc(201, 2, 50, 5, "/Users/dev/bin/git")},
		{"textconv shell git starts", esExecLine(esProc(202, 1, 100, 8, "/Library/Developer/CommandLineTools/usr/bin/git"), 202, 2, "/bin/sh"), esProc(202, 2, 100, 8, "/bin/sh")},
		{"git an agent starts", esExecLine(esProc(203, 1, 300, 3, "/usr/local/bin/node"), 203, 2, "/usr/bin/git"), esProc(203, 2, 300, 3, "/usr/bin/git")},
		{"no pidversion", strings.ReplaceAll(esExecLine(esProc(204, 1, 50, 5, esTestDaemonExe), 204, 2, "/usr/bin/git"), `"pidversion":2`, `"x":2`), strings.ReplaceAll(esProc(204, 2, 50, 5, "/usr/bin/git"), `"pidversion":2`, `"x":2`)},
	}
	for _, c := range cases {
		keepESLine([]byte(c.exec))
		if !keepESLine([]byte(esOpenBy(c.proc, "/Users/dev/repo/src/main.go"))) {
			t.Fatalf("%s: open dropped", c.name)
		}
	}
	// A tracked tool that execs an unlisted image under the same token is
	// no longer tracked.
	keepESLine([]byte(esExecLine(git, 100, 8, "/usr/bin/python3")))
	if !keepESLine([]byte(esOpenBy(esProc(100, 8, 50, 5, "/usr/bin/python3"), "/Users/dev/repo/a.py"))) {
		t.Fatal("an unlisted image kept its tool tracking")
	}
	// Tracking lasts esToolTTL.
	keepESLine([]byte(esExecLine(esProc(110, 1, 50, 5, esTestDaemonExe), 110, 2, "/usr/sbin/lsof")))
	lsof := esProc(110, 2, 50, 5, "/usr/sbin/lsof")
	if keepESLine([]byte(esOpenBy(lsof, "/Users/dev/repo/x"))) {
		t.Fatal("the daemon's lsof kept its open")
	}
	*now = now.Add(esToolTTL)
	if !keepESLine([]byte(esOpenBy(lsof, "/Users/dev/repo/x"))) {
		t.Fatal("tracking outlived esToolTTL")
	}
}

func TestIsESDaemonTool(t *testing.T) {
	for path, want := range map[string]bool{
		"/usr/bin/git": true, "/Library/Developer/CommandLineTools/usr/bin/git": true,
		"/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http": true,
		"/Library/Developer/CommandLineTools/usr/libexec/git-core/":                false,
		"/Library/Developer/CommandLineTools/usr/libexec/git-core/x/y":             false,
		"/opt/homebrew/bin/git": false, "/usr/local/bin/git": false, "/bin/sh": false, "git": false,
	} {
		if got := isESDaemonTool(path); got != want {
			t.Errorf("isESDaemonTool(%q) = %v, want %v", path, got, want)
		}
	}
}
