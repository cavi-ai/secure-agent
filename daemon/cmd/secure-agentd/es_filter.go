package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// The helper drops open events on system paths before they reach the spool:
// opens of OS libraries, frameworks, dyld caches, app-bundle resources and
// package-manager libraries carry much of eslogger's volume and none of the
// daemon's signal. Every other event type is kept, and an open is never
// dropped when the daemon's sensitive-path classifier matches its path.

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
	esEventMarker = []byte(`"event":{"`)
	esOpenKey     = []byte(`open":{`)
	esPathMarker  = []byte(`"path":"`)
)

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
// drops only open events whose path is system noise; a line it cannot read
// (malformed, unexpected shape) is kept. Byte scans first: the line is
// JSON-decoded only when eslogger's compact layout is absent, and the path
// string only when it holds escapes.
func keepESLine(line []byte) bool {
	i := bytes.Index(line, esEventMarker)
	if i < 0 {
		return keepESLineParsed(line)
	}
	rest := line[i+len(esEventMarker):]
	if !bytes.HasPrefix(rest, esOpenKey) {
		return true // exec, unlink, rename, tcc_modify
	}
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
		return !dropESOpenPath(body)
	}
	var path string
	if err := json.Unmarshal(quoted[:len(body)+2], &path); err != nil {
		return true
	}
	return !dropESOpenPath([]byte(path))
}

// keepESLineParsed is keepESLine's fallback for lines without eslogger's
// compact layout.
func keepESLineParsed(line []byte) bool {
	var env struct {
		Event struct {
			Open *struct {
				File struct {
					Path string `json:"path"`
				} `json:"file"`
			} `json:"open"`
		} `json:"event"`
	}
	if err := json.Unmarshal(line, &env); err != nil || env.Event.Open == nil {
		return true
	}
	return !dropESOpenPath([]byte(env.Event.Open.File.Path))
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

// dropESOpenPath reports whether an open of path is system noise that the
// sensitive-path classifier does not match.
func dropESOpenPath(path []byte) bool {
	if !isESNoisePath(path) {
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

// esFilterStats counts kept and dropped spool lines for the helper's
// once-a-minute log line.
type esFilterStats struct {
	since         time.Time
	kept, dropped uint64
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
	msg := fmt.Sprintf("es-collector: dropped %d of %d lines (system-path opens) in the last %s",
		s.dropped, s.kept+s.dropped, elapsed.Round(time.Second))
	*s = esFilterStats{since: now}
	return msg, true
}
