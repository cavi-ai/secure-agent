package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

const (
	// tailInterval is how often active transcript files are tailed for new lines.
	tailInterval = 200 * time.Millisecond
	// resolveInterval is how often the (expensive) recursive path discovery and
	// the active-set recomputation run.
	resolveInterval = 5 * time.Second
	// activeWindow is how recently a file must have been modified to be tailed
	// on the fast loop. Idle historical transcripts are skipped until they are
	// appended to again; they rejoin the active set within one resolveInterval,
	// and their byte offset is retained, so no appended lines are missed.
	activeWindow = 2 * time.Minute
)

type TranscriptScanner struct {
	bus   *bus.Bus
	paths []string
}

func NewTranscriptScanner(b *bus.Bus, paths []string) *TranscriptScanner {
	return &TranscriptScanner{
		bus:   b,
		paths: paths,
	}
}

type pluginLogLine struct {
	Tool     string `json:"tool"`
	PID      int32  `json:"pid"`
	TS       string `json:"ts"`
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
}

func ScanLine(line string) (event.Event, bool) {
	if line == "" {
		return event.Event{}, false
	}

	// 1. Check for credential redaction match
	if rule, found := redact.Detect(line); found {
		return event.Event{
			Kind:   event.KindTranscriptHit,
			TS:     time.Now(),
			Detail: rule,
		}, true
	}

	// 2. Check for plugin activity JSON line
	if strings.HasPrefix(strings.TrimSpace(line), "{") && strings.Contains(line, `"tool"`) {
		var pl pluginLogLine
		if err := json.Unmarshal([]byte(line), &pl); err == nil && pl.Tool != "" {
			ts := time.Now()
			if pl.TS != "" {
				if t, err := time.Parse(time.RFC3339Nano, pl.TS); err == nil {
					ts = t
				} else if t, err := time.Parse(time.RFC3339, pl.TS); err == nil {
					ts = t
				}
			}
			path := pl.FilePath
			if path == "" {
				path = pl.Command
			}
			return event.Event{
				Kind:   event.KindPluginAction,
				TS:     ts,
				PID:    pl.PID,
				Path:   path,
				Detail: pl.Tool,
			}, true
		}
	}

	return event.Event{}, false
}

func (ts *TranscriptScanner) Run(ctx context.Context) error {
	offsets := make(map[string]int64)

	// Targets split two ways. Directory targets (e.g. ~/.claude/projects) need a
	// recursive walk that is expensive when the tree holds thousands of files,
	// so they are re-walked only on the slow resolve cadence and further limited
	// to recently-modified files. File and glob targets (the hook activity log,
	// session logs) are cheap to resolve and are refreshed on every fast tail
	// tick, so real-time signals are picked up with low latency. Walking the
	// whole tree on every tail tick previously pegged the CPU at ~20%+.
	dirTargets, cheapTargets := ts.classifyTargets()
	cheapPaths := resolveGlobs(cheapTargets)
	dirPaths := activePaths(walkDirs(dirTargets))

	// Seed everything present at startup to EOF so old history is not replayed;
	// files that appear later are read from byte 0 (see tailFile), so genuinely
	// new session transcripts are captured whole.
	for _, p := range cheapPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			offsets[p] = fi.Size()
		}
	}
	for _, p := range dirPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			offsets[p] = fi.Size()
		}
	}

	tailTicker := time.NewTicker(tailInterval)
	defer tailTicker.Stop()
	resolveTicker := time.NewTicker(resolveInterval)
	defer resolveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resolveTicker.C:
			dirTargets, cheapTargets = ts.classifyTargets()
			dirPaths = activePaths(walkDirs(dirTargets))
		case <-tailTicker.C:
			cheapPaths = resolveGlobs(cheapTargets)
			for _, p := range cheapPaths {
				ts.tailFile(p, offsets)
			}
			for _, p := range dirPaths {
				ts.tailFile(p, offsets)
			}
		}
	}
}

// classifyTargets splits configured targets into directory targets (which need
// a recursive walk) and cheap targets (explicit files or globs). A target that
// does not currently exist is treated as cheap; it costs nothing until it
// appears.
func (ts *TranscriptScanner) classifyTargets() (dirs, cheap []string) {
	for _, p := range ts.paths {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			dirs = append(dirs, p)
		} else {
			cheap = append(cheap, p)
		}
	}
	return dirs, cheap
}

// walkDirs returns every .jsonl file beneath the given directories.
func walkDirs(dirs []string) []string {
	var res []string
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
			if err == nil && !de.IsDir() && strings.HasSuffix(path, ".jsonl") {
				res = append(res, path)
			}
			return nil
		})
	}
	return res
}

// resolveGlobs expands explicit-file and glob targets to the files that exist
// now. A target with no match yet is returned as-is so tailFile can pick it up
// the moment it appears.
func resolveGlobs(targets []string) []string {
	var res []string
	for _, p := range targets {
		matches, err := filepath.Glob(p)
		if err == nil && len(matches) > 0 {
			for _, m := range matches {
				if fi, mErr := os.Stat(m); mErr == nil && !fi.IsDir() {
					res = append(res, m)
				}
			}
		} else {
			res = append(res, p)
		}
	}
	return res
}

// activePaths returns the subset of paths modified within activeWindow. It runs
// on the slow resolve cadence so the fast tail loop can skip the thousands of
// idle historical transcripts that never change; an idle file rejoins the set
// within one resolveInterval of being appended to, and its offset is retained,
// so no appended lines are missed.
func activePaths(paths []string) []string {
	cutoff := time.Now().Add(-activeWindow)
	res := make([]string, 0, len(paths))
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.ModTime().After(cutoff) {
			res = append(res, p)
		}
	}
	return res
}

func (ts *TranscriptScanner) tailFile(p string, offsets map[string]int64) {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return
	}

	offset, tracked := offsets[p]
	if !tracked {
		// New file discovered after startup: tail from byte 0
		offset = 0
	}

	if fi.Size() < offset {
		offset = 0 // file truncated
	}
	if fi.Size() == offset {
		return // no new data
	}

	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	r := bufio.NewReader(f)
	newOffset := offset

	for {
		lineBytes, err := r.ReadBytes('\n')
		if len(lineBytes) > 0 {
			if bytes.HasSuffix(lineBytes, []byte("\n")) {
				newOffset += int64(len(lineBytes))
				line := strings.TrimRight(string(lineBytes), "\r\n")
				if e, ok := ScanLine(line); ok {
					ts.bus.Publish(e)
				}
			} else {
				// Partial line at EOF; do not advance past partial line, retry on next poll
				break
			}
		}
		if err != nil {
			break
		}
	}

	offsets[p] = newOffset
}
