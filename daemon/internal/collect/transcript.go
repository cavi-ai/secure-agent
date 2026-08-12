package collect

import (
	"bufio"
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
	Tool string `json:"tool"`
	PID  int32  `json:"pid"`
	TS   string `json:"ts"`
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
			return event.Event{
				Kind:   event.KindPluginAction,
				TS:     ts,
				PID:    pl.PID,
				Detail: pl.Tool,
			}, true
		}
	}

	return event.Event{}, false
}

func (ts *TranscriptScanner) Run(ctx context.Context) error {
	offsets := make(map[string]int64)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			expandedPaths := ts.resolvePaths()
			for _, p := range expandedPaths {
				ts.tailFile(p, offsets)
			}
		}
	}
}

func (ts *TranscriptScanner) resolvePaths() []string {
	var res []string
	for _, p := range ts.paths {
		matches, err := filepath.Glob(p)
		if err == nil && len(matches) > 0 {
			res = append(res, matches...)
		} else {
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

	offset := offsets[p]
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

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 64*1024)

	var bytesRead int64
	for scanner.Scan() {
		line := scanner.Text()
		bytesRead += int64(len(line)) + 1
		if e, ok := ScanLine(line); ok {
			ts.bus.Publish(e)
		}
	}

	offsets[p] = offset + bytesRead
}
