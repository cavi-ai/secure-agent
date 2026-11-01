package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// The helper drops open events on system paths before they reach the spool:
// opens of OS libraries, frameworks, dyld caches, app-bundle resources,
// package-manager libraries and the per-user temporary and cache roots carry
// much of eslogger's volume and none of the daemon's signal. Opens by the
// user daemon itself (its disk-usage walks, transcript reads) and by the
// system tools it runs (es_tools.go) are dropped on any path. An open is never dropped when the daemon's sensitive-path
// classifier matches its path or the path is a configuration profile file. A create is kept only when it names a
// launchd agent or daemon directory, or an app bundle, installer package or
// configuration profile file that a later Gatekeeper override or profile
// install is traced back to. Every other event type is kept.

// esNoisePrefixes are the open-path prefixes whose opens are dropped.
var esNoisePrefixes = []string{
	"/System/", // except esDataVolumePrefix
	"/usr/lib/", "/usr/libexec/", "/usr/bin/", "/usr/sbin/", "/usr/share/",
	"/bin/", "/sbin/",
	"/Library/Apple/", "/Library/Developer/CommandLineTools/",
	"/opt/homebrew/Cellar/",
	"/dev/fd/", "/dev/ttys",
	"/private/var/db/timezone/", "/private/var/db/KernelExtensionManagement/",
	"/private" + esSpoolDir + "/", // the daemon's own spool reads (ES reports the /private path)
	"/private/var/folders/",       // per-user $TMPDIR and cache roots
}

// esDataVolumePrefix is the firmlinked data volume: user files reached
// through it are not system paths.
const esDataVolumePrefix = "/System/Volumes/Data/"

// esNoiseExact are single paths whose opens are dropped.
var esNoiseExact = map[string]bool{
	"/":                  true,
	"/dev/null":          true,
	"/dev/zero":          true,
	"/dev/random":        true,
	"/dev/urandom":       true,
	"/dev/dtracehelper":  true,
	"/dev/autofs_nowait": true,
	"/dev/console":       true,
	"/dev/tty":           true,
	"/dev/ptmx":          true,
}

var (
	esEventMarker      = []byte(`"event":{"`)
	esOpenKey          = []byte(`open":{`)
	esCreateKey        = []byte(`create":{`)
	esExecKey          = []byte(`exec":{`)
	esPathMarker       = []byte(`"path":"`)
	esExecutableMarker = []byte(`"executable":{`)
)

// esDaemonExe is the user daemon's executable in the collector's app bundle,
// plain and as eslogger writes it (every slash escaped); both are empty when
// the collector does not know it.
var esDaemonExe, esDaemonExeEscaped []byte

// setESDaemonExe records the user daemon's executable path.
func setESDaemonExe(path string) {
	esDaemonExe = []byte(path)
	esDaemonExeEscaped = []byte(strings.ReplaceAll(path, "/", `\/`))
}

// openedByDaemon reports whether head, an eslogger line up to its event
// object, names the user daemon as the process.
func openedByDaemon(head []byte) bool {
	if len(esDaemonExe) == 0 {
		return false
	}
	k := bytes.Index(head, esExecutableMarker)
	if k < 0 {
		return false
	}
	rest := head[k+len(esExecutableMarker):]
	j := bytes.Index(rest, esPathMarker)
	if j < 0 {
		return false
	}
	body, _, ok := jsonStringBody(rest[j+len(esPathMarker):])
	return ok && (bytes.Equal(body, esDaemonExe) || bytes.Equal(body, esDaemonExeEscaped))
}

// esLaunchItemDirs are the launchd agent and daemon directories, system-wide
// and under each home, as plain and as JSON-escaped ("\/") text: eslogger
// escapes every slash.
var esLaunchItemDirs = [][]byte{
	[]byte("/Library/LaunchAgents"), []byte("/Library/LaunchDaemons"),
	[]byte(`\/Library\/LaunchAgents`), []byte(`\/Library\/LaunchDaemons`),
}

// namesLaunchItemDir reports whether an eslogger line mentions a launchd
// agent or daemon directory anywhere.
func namesLaunchItemDir(line []byte) bool {
	for _, d := range esLaunchItemDirs {
		if bytes.Contains(line, d) {
			return true
		}
	}
	return false
}

// esTrustSubjectEnds are the JSON string endings of an app bundle, installer
// package or configuration profile path or file name.
var esTrustSubjectEnds = [][]byte{
	[]byte(`.app"`), []byte(`.pkg"`), []byte(`.mpkg"`), []byte(`.mobileconfig"`),
}

// namesTrustSubject reports whether an eslogger line holds a string ending in
// an app bundle, installer package or configuration profile name.
func namesTrustSubject(line []byte) bool {
	for _, s := range esTrustSubjectEnds {
		if bytes.Contains(line, s) {
			return true
		}
	}
	return false
}

// esSensitive is the daemon's sensitive-path classifier over the compiled-in
// config (os.DevNull as the overlay: the root helper reads no user file).
// nil when the config does not load; then no open is dropped.
var esSensitive = sync.OnceValue(func() sensitive.Classifier {
	cfg, err := config.Load(os.DevNull)
	if err != nil {
		log.Printf("es-collector: sensitive config: %v — keeping every open event", err)
		return nil
	}
	return sensitive.New(cfg)
})

// keepESLine reports whether one eslogger JSON line goes to the spool. It
// drops open events whose path is system noise or whose process is the user
// daemon, and creates that name neither a launch-item directory nor a trust
// subject; a line it cannot read
// (malformed, unexpected shape) is kept. Byte scans first: the line is JSON-decoded only when
// eslogger's compact layout is absent, and the path string only when it
// holds escapes.
func keepESLine(line []byte) bool {
	i := bytes.Index(line, esEventMarker)
	if i < 0 {
		return keepESLineParsed(line)
	}
	rest := line[i+len(esEventMarker):]
	if bytes.HasPrefix(rest, esCreateKey) {
		return namesLaunchItemDir(rest) || namesTrustSubject(rest)
	}
	if bytes.HasPrefix(rest, esExecKey) {
		esTools.noteExec(line, line[:i])
		return true
	}
	if !bytes.HasPrefix(rest, esOpenKey) {
		return true // every event other than open
	}
	byDaemon := openedByDaemon(line[:i]) || esTools.ran(line[:i])
	rest = rest[len(esOpenKey):]
	j := bytes.Index(rest, esPathMarker)
	if j < 0 {
		return keepESLineParsed(line)
	}
	quoted := rest[j+len(esPathMarker)-1:] // from the opening quote
	body, escaped, ok := jsonStringBody(quoted[1:])
	if !ok {
		return true // truncated line
	}
	if !escaped {
		return !dropESOpenPath(body, byDaemon)
	}
	var path string
	if err := json.Unmarshal(quoted[:len(body)+2], &path); err != nil {
		return true
	}
	return !dropESOpenPath([]byte(path), byDaemon)
}

// keepESLineParsed is keepESLine's fallback for lines without eslogger's
// compact layout.
func keepESLineParsed(line []byte) bool {
	var env struct {
		Process struct {
			Executable struct {
				Path string `json:"path"`
			} `json:"executable"`
		} `json:"process"`
		Event struct {
			Open *struct {
				File struct {
					Path string `json:"path"`
				} `json:"file"`
			} `json:"open"`
			Create json.RawMessage `json:"create"`
		} `json:"event"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return true
	}
	if env.Event.Create != nil {
		return namesLaunchItemDir(env.Event.Create) || namesTrustSubject(env.Event.Create)
	}
	if env.Event.Open == nil {
		return true
	}
	byDaemon := len(esDaemonExe) > 0 && env.Process.Executable.Path == string(esDaemonExe)
	return !dropESOpenPath([]byte(env.Event.Open.File.Path), byDaemon)
}

// jsonStringBody returns a JSON string's body up to its closing quote (b
// starts just past the opening quote), whether the body holds escapes, and
// false when the closing quote is missing.
func jsonStringBody(b []byte) (body []byte, escaped, ok bool) {
	for k := 0; k < len(b); k++ {
		switch b[k] {
		case '\\':
			escaped = true
			k++
		case '"':
			return b[:k], escaped, true
		}
	}
	return nil, escaped, false
}

// dropESOpenPath reports whether an open of path, by the user daemon or of a
// system noise path, is not of a configuration profile file and does not
// match the sensitive-path classifier.
func dropESOpenPath(path []byte, byDaemon bool) bool {
	if !(byDaemon || isESNoisePath(path)) || bytes.HasSuffix(path, []byte(".mobileconfig")) {
		return false
	}
	c := esSensitive()
	if c == nil {
		return false
	}
	_, sensitiveMatch := c.Match(string(path))
	return !sensitiveMatch
}

func isESNoisePath(path []byte) bool {
	if esNoiseExact[string(path)] {
		return true
	}
	for _, p := range esNoisePrefixes {
		if bytes.HasPrefix(path, []byte(p)) {
			return !bytes.HasPrefix(path, []byte(esDataVolumePrefix))
		}
	}
	if rest, ok := bytes.CutPrefix(path, []byte("/Applications/")); ok {
		return bytes.Contains(rest, []byte(".app/Contents/"))
	}
	if rest, ok := bytes.CutPrefix(path, []byte("/Users/")); ok {
		if k := bytes.IndexByte(rest, '/'); k > 0 {
			return bytes.HasPrefix(rest[k:], []byte("/Library/Caches/"))
		}
	}
	return false
}

// esFilterStats counts kept and dropped spool lines, and the kept lines'
// bytes as eslogger wrote them and as written to the spool, for the helper's
// once-a-minute log line.
type esFilterStats struct {
	since                 time.Time
	kept, dropped         uint64
	keptBytes, wroteBytes uint64
}

// report returns the log line for the interval ending at now and resets the
// counters, or false while the interval is under a minute.
func (s *esFilterStats) report(now time.Time) (string, bool) {
	if s.since.IsZero() {
		s.since = now
	}
	elapsed := now.Sub(s.since)
	if elapsed < time.Minute {
		return "", false
	}
	msg := fmt.Sprintf("es-collector: dropped %d of %d lines (system and temp-path opens) in the last %s; wrote %d KB for %d KB kept",
		s.dropped, s.kept+s.dropped, elapsed.Round(time.Second), s.wroteBytes>>10, s.keptBytes>>10)
	*s = esFilterStats{since: now}
	return msg, true
}
