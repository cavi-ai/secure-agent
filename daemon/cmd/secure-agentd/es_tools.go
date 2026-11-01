package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The user daemon runs system tools of its own: git for the worktree and
// cleanup scans, lsof, ps and netstat for its samplers. Their opens are the
// daemon's activity, and git's walk whole worktrees, so the collector drops
// them as it drops the daemon's own: for a process the daemon started whose
// every exec ran one of these root-owned system binaries. The daemon also
// starts agents (the system agent, agent asks); those run other executables
// and keep every event, as does anything a tool starts that is not listed
// (a textconv or gpg program git runs), and a git found anywhere else on
// PATH. Sensitive-path opens are kept either way (dropESOpenPath).

// esDaemonTools are the executables, by exact path, whose processes the
// daemon starts and the collector tracks.
var esDaemonTools = map[string]bool{
	"/usr/bin/git":   true, // xcrun shim: execs the developer-tools git below
	"/usr/bin/xcrun": true,
	"/Library/Developer/CommandLineTools/usr/bin/git":        true,
	"/Applications/Xcode.app/Contents/Developer/usr/bin/git": true,
	"/usr/sbin/lsof":    true,
	"/usr/sbin/netstat": true,
	"/bin/ps":           true,
	"/usr/bin/vm_stat":  true,
	"/usr/bin/pmset":    true,
	"/bin/launchctl":    true,
}

// esDaemonToolDirs hold git's own helper executables.
var esDaemonToolDirs = []string{
	"/Library/Developer/CommandLineTools/usr/libexec/git-core/",
	"/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/",
}

func isESDaemonTool(path string) bool {
	if esDaemonTools[path] {
		return true
	}
	for _, d := range esDaemonToolDirs {
		if rest, ok := strings.CutPrefix(path, d); ok && rest != "" && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}

const (
	// esToolTTL bounds how long a tracked tool process drops its opens; a
	// longer run keeps them.
	esToolTTL = 10 * time.Minute
	// esToolMax bounds the tracked processes; past it tracking starts over,
	// which keeps opens rather than dropping them.
	esToolMax = 4096
)

// esToken is a process by audit token: pidversion tells apart processes
// that reuse a pid.
type esToken struct{ pid, version int64 }

type esAuditToken struct {
	PID        int64 `json:"pid"`
	PIDVersion int64 `json:"pidversion"`
}

func (a *esAuditToken) token() (esToken, bool) {
	if a == nil || a.PID == 0 || a.PIDVersion == 0 {
		return esToken{}, false
	}
	return esToken{a.PID, a.PIDVersion}, true
}

// esToolTracker holds the daemon's tool processes, by when they were seen.
type esToolTracker struct {
	mu    sync.Mutex
	procs map[esToken]time.Time
}

var esTools = newESToolTracker()

func newESToolTracker() *esToolTracker { return &esToolTracker{procs: map[esToken]time.Time{}} }

// noteExec updates the tracker from an exec line whose head (the line up to
// its event object) is head: the new image is tracked when the exec'ing
// process is the daemon, a tracked tool or a tracked tool's child and the
// image is a listed tool; otherwise it is not.
func (t *esToolTracker) noteExec(line, head []byte) {
	byDaemon := openedByDaemon(head)
	t.mu.Lock()
	idle := len(t.procs) == 0
	t.mu.Unlock()
	if idle && !byDaemon {
		return
	}
	var env struct {
		Process struct {
			AuditToken       *esAuditToken `json:"audit_token"`
			ParentAuditToken *esAuditToken `json:"parent_audit_token"`
		} `json:"process"`
		Event struct {
			Exec *struct {
				Target struct {
					AuditToken *esAuditToken `json:"audit_token"`
					Executable struct {
						Path string `json:"path"`
					} `json:"executable"`
				} `json:"target"`
			} `json:"exec"`
		} `json:"event"`
	}
	if json.Unmarshal(line, &env) != nil || env.Event.Exec == nil {
		return
	}
	target, ok := env.Event.Exec.Target.AuditToken.token()
	if !ok {
		return
	}
	now := esNow()
	t.mu.Lock()
	defer t.mu.Unlock()
	from := byDaemon || t.freshLocked(env.Process.AuditToken, now) || t.freshLocked(env.Process.ParentAuditToken, now)
	delete(t.procs, target)
	if !from || !isESDaemonTool(env.Event.Exec.Target.Executable.Path) {
		return
	}
	if len(t.procs) >= esToolMax {
		for k, at := range t.procs {
			if now.Sub(at) >= esToolTTL {
				delete(t.procs, k)
			}
		}
		if len(t.procs) >= esToolMax {
			clear(t.procs)
		}
	}
	t.procs[target] = now
}

func (t *esToolTracker) freshLocked(a *esAuditToken, now time.Time) bool {
	k, ok := a.token()
	if !ok {
		return false
	}
	at, ok := t.procs[k]
	return ok && now.Sub(at) < esToolTTL
}

// ran reports whether head, an eslogger line up to its event object, names
// a tracked tool process.
func (t *esToolTracker) ran(head []byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.procs) == 0 {
		return false
	}
	a, ok := headAuditToken(head)
	return ok && t.freshLocked(&a, esNow())
}

var (
	esAuditTokenMarker = []byte(`"audit_token":{`)
	esPIDMarker        = []byte(`"pid":`)
	esPIDVersionMarker = []byte(`"pidversion":`)
)

// headAuditToken reads the process's audit token from head without decoding
// it: the first "audit_token" key is the process's own (its parent's and
// responsible process's are keyed parent_audit_token and
// responsible_audit_token), and the token object holds only numbers.
func headAuditToken(head []byte) (esAuditToken, bool) {
	i := bytes.Index(head, esAuditTokenMarker)
	if i < 0 {
		return esAuditToken{}, false
	}
	obj := head[i+len(esAuditTokenMarker):]
	end := bytes.IndexByte(obj, '}')
	if end < 0 {
		return esAuditToken{}, false
	}
	obj = obj[:end]
	pid, ok1 := jsonNumberAfter(obj, esPIDMarker)
	version, ok2 := jsonNumberAfter(obj, esPIDVersionMarker)
	return esAuditToken{PID: pid, PIDVersion: version}, ok1 && ok2
}

func jsonNumberAfter(b, marker []byte) (int64, bool) {
	i := bytes.Index(b, marker)
	if i < 0 {
		return 0, false
	}
	rest := b[i+len(marker):]
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	v, err := strconv.ParseInt(string(rest[:n]), 10, 64)
	return v, err == nil
}
