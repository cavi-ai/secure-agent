package collect

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HarnessTranscriptGlobs are the places each harness writes its session
// transcripts under home, as globs whose `*` matches exactly one path
// segment. Discovery expands these shapes instead of walking the harness
// trees, which also hold tens of thousands of files that are never
// transcripts.
func HarnessTranscriptGlobs(home string) []string {
	claude := filepath.Join(home, ".claude", "projects")
	cursor := filepath.Join(home, ".cursor", "projects")
	return []string{
		// Claude Code: one transcript per session, plus the subagent and
		// workflow-agent transcripts under the session's directory.
		filepath.Join(claude, "*", "*.jsonl"),
		filepath.Join(claude, "*", "*", "subagents", "*.jsonl"),
		filepath.Join(claude, "*", "*", "subagents", "workflows", "*", "*.jsonl"),
		// Cursor agent transcripts and their subagents; the rest of a Cursor
		// project tree is workspace state.
		filepath.Join(cursor, "*", "agent-transcripts", "*", "*.jsonl"),
		filepath.Join(cursor, "*", "agent-transcripts", "*", "subagents", "*.jsonl"),
		CodexRolloutGlob(filepath.Join(home, ".codex")),
		// Antigravity (agy): only the full transcript — transcript.jsonl and
		// the chunk files carry the same steps again.
		filepath.Join(home, ".gemini", "antigravity-cli", "brain", "*", ".system_generated", "logs", "transcript_full.jsonl"),
	}
}

// CodexRolloutGlob is the rollout shape under one CODEX_HOME:
// sessions/YYYY/MM/DD/rollout-*.jsonl.
func CodexRolloutGlob(codexHome string) string {
	return filepath.Join(codexHome, "sessions", "*", "*", "*", "rollout-*.jsonl")
}

// found is one file a discovery pass matched, with the size and modification
// time from the stat that matched it: seeding and the active set are decided
// from this stat, never a second one.
type found struct {
	path string
	size int64
	mod  time.Time
}

// readDirFunc lists one directory: os.ReadDir in production, a counting
// wrapper in tests.
type readDirFunc func(string) ([]os.DirEntry, error)

// hasMeta reports whether a path segment holds glob syntax.
func hasMeta(s string) bool {
	return strings.ContainsAny(s, `*?[\`)
}

// statFile stats one candidate; directories and missing files are not found.
func statFile(p string) (found, bool) {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return found{}, false
	}
	return found{path: p, size: fi.Size(), mod: fi.ModTime()}, true
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// globFiles expands one glob target the way filepath.Glob does — each `*`
// matches one path segment and directories along the way, never recursively
// — but lists only the directories the pattern names: literal segments are
// joined without a listing, and a literal final segment costs one stat.
// Each matched regular file is stat'ed once.
func globFiles(pattern string, readDir readDirFunc) []found {
	sep := string(filepath.Separator)
	segs := strings.Split(filepath.Clean(pattern), sep)
	i := 0
	for i < len(segs)-1 && !hasMeta(segs[i]) {
		i++
	}
	root := strings.Join(segs[:i], sep)
	if root == "" {
		root = "."
		if strings.HasPrefix(pattern, sep) {
			root = sep
		}
	}
	dirs := []string{root}
	var out []found
	for j := i; j < len(segs) && len(dirs) > 0; j++ {
		seg, last := segs[j], j == len(segs)-1
		if !hasMeta(seg) {
			for k := range dirs {
				dirs[k] = filepath.Join(dirs[k], seg)
			}
			if last {
				for _, p := range dirs {
					if f, ok := statFile(p); ok {
						out = append(out, f)
					}
				}
			}
			continue
		}
		var next []string
		for _, d := range dirs {
			entries, err := readDir(d)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ok, _ := filepath.Match(seg, e.Name()); !ok {
					continue
				}
				p := filepath.Join(d, e.Name())
				if last {
					if f, ok := statFile(p); ok {
						out = append(out, f)
					}
					continue
				}
				if e.IsDir() {
					next = append(next, p)
				} else if e.Type()&os.ModeSymlink != 0 {
					if fi, err := os.Stat(p); err == nil && fi.IsDir() {
						next = append(next, p)
					}
				}
			}
		}
		dirs = next
	}
	return out
}

// walkDir returns every .jsonl file beneath one directory target. It is the
// fallback for a configured directory that no harness shape describes, and
// it reads every directory in the tree on every resolve pass.
func walkDir(dir string) []found {
	var res []found
	_ = filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		// agy writes the same steps three ways (transcript.jsonl,
		// transcript_full.jsonl, and chunk files); trace only the full
		// one so a step is never emitted — or redaction-scanned — twice.
		if strings.Contains(filepath.ToSlash(path), "/antigravity-cli/brain/") {
			if !strings.HasSuffix(path, "/transcript_full.jsonl") {
				return nil
			}
		}
		if f, ok := statFile(path); ok {
			res = append(res, f)
		}
		return nil
	})
	return res
}

// activePaths returns the files modified within window before now, decided
// from the discovery pass's own stat. The fast tail loop visits only these;
// an idle file rejoins the set within one resolve interval of being appended
// to, and its offset is retained, so no appended lines are missed.
func activePaths(files []found, now time.Time, window time.Duration) []string {
	cutoff := now.Add(-window)
	res := make([]string, 0, len(files))
	for _, f := range files {
		if f.mod.After(cutoff) {
			res = append(res, f.path)
		}
	}
	return res
}
