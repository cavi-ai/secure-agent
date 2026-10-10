package collect

import (
	"io"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// traceSession normalizes the harness-specific identity and sighting rules.
type traceSession struct {
	ID, Harness, Workspace, Origin string
	At                             time.Time
}

type traceLineResult struct {
	Events  []event.Event
	Session traceSession
	Parsed  bool
}

type jsonlFile struct {
	parse   func(string) traceLineResult
	session func() string
}

type jsonlAdapter struct {
	harness string
	matches func(string) bool
	open    func(string, int64, io.ReaderAt) *jsonlFile
}

// Adding a JSONL harness requires one adapter here. Path recognition, parser
// creation, restart priming, and identity all cross this same seam.
var jsonlAdapters = []jsonlAdapter{
	{"claude", IsClaudeTranscriptPath, func(_ string, _ int64, _ io.ReaderAt) *jsonlFile {
		t := NewClaudeTracer()
		return &jsonlFile{session: t.Session, parse: func(line string) traceLineResult {
			evs, cwd, ok := t.ParseLine(line)
			r := traceLineResult{Events: evs, Parsed: ok}
			if ok && len(evs) > 0 {
				r.Session = traceSession{ID: evs[0].SessionID, Harness: "claude", Workspace: cwd, At: evs[0].TS}
			}
			return r
		}}
	}},
	{"codex", IsCodexRolloutPath, func(path string, offset int64, source io.ReaderAt) *jsonlFile {
		t := NewCodexTracer(path)
		if offset > 0 {
			t.Prime(io.NewSectionReader(source, 0, offset))
		}
		return &jsonlFile{session: func() string { id, _ := t.Session(); return id }, parse: func(line string) traceLineResult {
			evs, ok := t.ParseLine(line)
			r := traceLineResult{Events: evs, Parsed: ok || len(evs) > 0}
			if r.Parsed {
				id, cwd := t.Session()
				r.Session = traceSession{ID: id, Harness: "codex", Workspace: cwd, Origin: CodexOrigin(path), At: time.Now()}
			}
			return r
		}}
	}},
	{"cursor", IsCursorTranscriptPath, func(path string, _ int64, _ io.ReaderAt) *jsonlFile {
		t := NewCursorTracer(path)
		return &jsonlFile{session: func() string { id, _ := t.Session(); return id }, parse: func(line string) traceLineResult {
			evs, ok := t.ParseLine(line)
			r := traceLineResult{Events: evs, Parsed: ok}
			if ok && len(evs) > 0 {
				id, cwd := t.Session()
				r.Session = traceSession{ID: id, Harness: "cursor", Workspace: cwd, At: evs[0].TS}
			}
			return r
		}}
	}},
	{"antigravity", IsAGYTranscriptPath, func(path string, _ int64, _ io.ReaderAt) *jsonlFile {
		t := NewAGYTracer(path)
		return &jsonlFile{session: func() string { id, _ := t.Session(); return id }, parse: func(line string) traceLineResult {
			evs, ok := t.ParseLine(line)
			r := traceLineResult{Events: evs, Parsed: ok}
			if ok && len(evs) > 0 {
				id, cwd := t.Session()
				r.Session = traceSession{ID: id, Harness: "antigravity", Workspace: cwd, At: evs[0].TS}
			}
			return r
		}}
	}},
}

func adapterForPath(path string) *jsonlAdapter {
	for i := range jsonlAdapters {
		if jsonlAdapters[i].matches(path) {
			return &jsonlAdapters[i]
		}
	}
	return nil
}

func harnessForPath(path string) string {
	if a := adapterForPath(path); a != nil {
		return a.harness
	}
	return "unknown"
}

// jsonlTracers is owned by the scanner's single tail goroutine. Reset retires
// state only when the scanner detects source replacement or deletion.
type jsonlTracers struct{ files map[string]*jsonlFile }

func (t *jsonlTracers) Parse(path, line string, offset int64, source io.ReaderAt) traceLineResult {
	f := t.files[path]
	if f == nil {
		a := adapterForPath(path)
		if a == nil {
			return traceLineResult{}
		}
		f = a.open(path, offset, source)
		if t.files == nil {
			t.files = map[string]*jsonlFile{}
		}
		t.files[path] = f
	}
	return f.parse(line)
}

func (t *jsonlTracers) Session(path string) string {
	if f := t.files[path]; f != nil {
		return f.session()
	}
	return ""
}

func (t *jsonlTracers) Reset(path string) { delete(t.files, path) }
