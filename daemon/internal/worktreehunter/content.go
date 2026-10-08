package worktreehunter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The content check answers "is this branch's work on the default branch?"
// when neither ancestry nor a patch id says so: a squash commit that carries
// extra edits, a repository whose history was rewritten, a directory that was
// renamed since. The branch is merged by content when every line it adds is
// present in the file that stands in for it on the default branch, every
// binary it adds is a blob the default branch has, and every file it deletes
// is gone from the default branch. Anything the check cannot measure inside
// its bounds is unknown, never guessed.

const (
	contentMaxFiles     = 1000    // changed files
	contentMaxLines     = 100000  // added lines
	contentMaxDiffBytes = 8 << 20 // the combined diff
	contentMaxRawBytes  = 1 << 20 // the changed-file list
	contentMaxPaths     = 200000  // default-branch paths indexed by basename
	contentMaxTies      = 32      // equally good counterparts for one file
	contentMaxBlobBytes = 4 << 20 // one counterpart read as text
	pathListTimeout     = 30 * time.Second
	reflogCreated       = "branch: Created from"

	extendedMinWords = 3   // a shorter line never matches in a longer form
	extendedMinCap   = 3   // extended lines allowed however few lines there are
	extendedMaxTries = 200 // missing lines searched for a longer form
)

// contentMaxReadBytes bounds the counterpart content one check reads (a
// variable so a test can lower it).
var contentMaxReadBytes = 32 << 20

// errContentBound marks a diff, list or blob over the check's bounds.
var errContentBound = errors.New("content check bound exceeded")

// mergeVerdict is what mergeState learned: the verdict and, when the content
// check ran to the end, what it measured.
type mergeVerdict struct {
	state     string
	lines     int
	missing   int
	extended  int  // lines the default branch has only in a longer form
	unrelated bool // HEAD shares no commit with the default branch
}

// mergeBaseOf is `git merge-base HEAD ref`. ok is false when the histories
// share no commit (git exits 1); any other failure is an error.
func mergeBaseOf(ctx context.Context, dir, ref string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	var out bytes.Buffer
	cmd := gitCommand(ctx, dir, "merge-base", "HEAD", ref)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(out.String()), true, nil
}

// forkBase returns the commit a branch's own work is measured from: its
// merge-base with def or, when the histories share none (the default branch
// was rewritten), the commit the branch was created at. viaMergeBase tells
// the two apart; base is "" when there is neither.
func forkBase(ctx context.Context, dir, branch, def string) (base string, viaMergeBase bool, err error) {
	mb, ok, err := mergeBaseOf(ctx, dir, def)
	if err != nil {
		return "", false, err
	}
	if ok {
		return mb, true, nil
	}
	return reflogForkPoint(ctx, dir, branch), false, nil
}

// reflogForkPoint is the commit the branch's reflog says it was created at,
// provided that entry is the oldest one left and HEAD still descends from it.
// An expired reflog starts mid-history; its oldest entry would hide the
// commits before it, so only a creation entry counts.
func reflogForkPoint(ctx context.Context, dir, branch string) string {
	if branch == "" {
		return ""
	}
	out, err := git(ctx, dir, "reflog", "show", "--format=%H%x09%gs", "refs/heads/"+branch)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	sha, subject, ok := strings.Cut(lines[len(lines)-1], "\t")
	if !ok || len(sha) < 40 || !strings.HasPrefix(subject, reflogCreated) {
		return ""
	}
	if anc, err := gitOK(ctx, dir, "merge-base", "--is-ancestor", sha, "HEAD"); err != nil || !anc {
		return ""
	}
	return sha
}

// gitLimited is git whose stdout is read to limit bytes; more is
// errContentBound and the process is killed.
func gitLimited(ctx context.Context, dir string, limit int64, args ...string) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := gitCommand(ctx, dir, args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(data)) > limit || readErr != nil {
		cancel()
		_ = cmd.Wait()
		if readErr != nil {
			return "", readErr
		}
		return "", errContentBound
	}
	if err := cmd.Wait(); err != nil {
		msg, _, _ := strings.Cut(strings.TrimSpace(errb.String()), "\n")
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", args[0], msg)
	}
	return string(data), nil
}

// change is one entry of the branch's `git diff --raw` against its base.
type change struct {
	status  byte // A, M or D
	oldMode string
	newMode string
	oid     string // the branch's blob; zeros for a deletion
	path    string
}

// readChanges lists what the branch changed since base, one entry per path.
// Type changes, submodule pointers and paths with a newline are not measured.
func readChanges(ctx context.Context, dir, base string) ([]change, error) {
	out, err := gitLimited(ctx, dir, contentMaxRawBytes, "diff", "--raw", "-z", "--no-renames",
		"--no-abbrev", "--no-ext-diff", "--no-textconv", base, "HEAD")
	if err != nil {
		return nil, err
	}
	toks := strings.Split(out, "\x00")
	var cs []change
	for i := 0; i+1 < len(toks); i += 2 {
		f := strings.Fields(strings.TrimPrefix(toks[i], ":"))
		if !strings.HasPrefix(toks[i], ":") || len(f) != 5 || len(f[4]) != 1 {
			return nil, fmt.Errorf("unexpected diff --raw record %q", toks[i])
		}
		c := change{oldMode: f[0], newMode: f[1], oid: f[3], status: f[4][0], path: toks[i+1]}
		switch {
		case c.status != 'A' && c.status != 'M' && c.status != 'D',
			c.oldMode == "160000" || c.newMode == "160000",
			strings.Contains(c.path, "\n"):
			return nil, errContentBound
		}
		cs = append(cs, c)
		if len(cs) > contentMaxFiles {
			return nil, errContentBound
		}
	}
	return cs, nil
}

// fileDiff is what the zero-context patch says about one changed file.
type fileDiff struct {
	added  []string // trimmed, non-blank
	binary bool
}

// readPatch parses the branch's combined diff into one fileDiff per change,
// in the order `diff --raw` lists them.
func readPatch(ctx context.Context, dir, base string, files int) ([]fileDiff, error) {
	out, err := gitLimited(ctx, dir, contentMaxDiffBytes, "diff", "-U0", "--no-color", "--no-ext-diff",
		"--no-textconv", "--no-renames", "--submodule=short", base, "HEAD")
	if err != nil {
		return nil, err
	}
	var diffs []fileDiff
	inHunk := false
	total := 0
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			diffs = append(diffs, fileDiff{})
			inHunk = false
		case len(diffs) == 0:
		case !inHunk && strings.HasPrefix(line, "@@"):
			inHunk = true
		case !inHunk && (strings.HasPrefix(line, "Binary files ") || line == "GIT binary patch"):
			diffs[len(diffs)-1].binary = true
		case inHunk && strings.HasPrefix(line, "+"):
			l := normalizeLine(line[1:])
			if l == "" {
				continue
			}
			if total++; total > contentMaxLines {
				return nil, errContentBound
			}
			d := &diffs[len(diffs)-1]
			d.added = append(d.added, l)
		}
	}
	if len(diffs) != files {
		return nil, fmt.Errorf("diff lists %d files, diff --raw %d", len(diffs), files)
	}
	return diffs, nil
}

// normalizeLine drops trailing whitespace and carriage returns, so a CRLF
// checkout and an LF one compare equal.
func normalizeLine(s string) string { return strings.TrimRightFunc(s, unicode.IsSpace) }

// pathIndex lists the default branch's file paths by basename. A tree over
// contentMaxPaths is not indexed (big): counterparts are then looked up by
// exact path in the object database only.
type pathIndex struct {
	big    bool
	byBase map[string][]string
}

func (ix *pathIndex) has(p string) bool {
	for _, q := range ix.byBase[path.Base(p)] {
		if q == p {
			return true
		}
	}
	return false
}

// counterparts names the default-branch files that stand in for p: p itself
// when it exists there, else those with p's basename and the longest common
// trailing path. More than contentMaxTies equally good ones is a bound.
func (ix *pathIndex) counterparts(p string) ([]string, error) {
	if ix.big || ix.has(p) {
		return []string{p}, nil
	}
	mine := strings.Split(p, "/")
	best := 0
	var out []string
	for _, q := range ix.byBase[path.Base(p)] {
		theirs := strings.Split(q, "/")
		n := 0
		for n < len(mine) && n < len(theirs) && mine[len(mine)-1-n] == theirs[len(theirs)-1-n] {
			n++
		}
		switch {
		case n > best:
			best, out = n, []string{q}
		case n == best:
			out = append(out, q)
		}
	}
	if len(out) > contentMaxTies {
		return nil, errContentBound
	}
	return out, nil
}

// loadPathIndex reads the default branch's file list.
func loadPathIndex(ctx context.Context, dir, def string) (*pathIndex, error) {
	ctx, cancel := context.WithTimeout(ctx, pathListTimeout)
	defer cancel()
	cmd := gitCommand(ctx, dir, "ls-tree", "-r", "--name-only", "-z", def)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ix := &pathIndex{byBase: map[string][]string{}}
	r := bufio.NewReaderSize(stdout, 256<<10)
	n := 0
	for {
		p, err := r.ReadString(0)
		if p = strings.TrimSuffix(p, "\x00"); p != "" {
			if n++; n > contentMaxPaths {
				cancel()
				_ = cmd.Wait()
				return &pathIndex{big: true}, nil
			}
			b := path.Base(p)
			ix.byBase[b] = append(ix.byBase[b], p)
		}
		if err != nil {
			if err != io.EOF {
				cancel()
				_ = cmd.Wait()
				return nil, err
			}
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git ls-tree: %w", err)
	}
	return ix, nil
}

// repoPaths returns the default branch's path index, computed at most once
// per scan and reused across scans while the branch tip is unchanged.
func (h *Hunter) repoPaths(ctx context.Context, rs *repoScan) (*pathIndex, error) {
	rs.pathOnce.Do(func() {
		tipOut, err := git(ctx, rs.ref.Main, "rev-parse", rs.def)
		if err != nil {
			rs.pathErr = err
			return
		}
		tip := strings.TrimSpace(tipOut)
		h.pathMu.Lock()
		c, ok := h.pathIndexes[rs.ref.Common]
		h.pathMu.Unlock()
		if ok && c.tip == tip {
			rs.paths = c.ix
			return
		}
		rs.paths, rs.pathErr = loadPathIndex(ctx, rs.ref.Main, rs.def)
		if rs.pathErr == nil {
			h.pathMu.Lock()
			h.pathIndexes[rs.ref.Common] = pathCache{tip: tip, ix: rs.paths}
			h.pathMu.Unlock()
		}
	})
	return rs.paths, rs.pathErr
}

// blobReader is one `git cat-file --batch` process.
type blobReader struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func startBlobReader(ctx context.Context, dir string) (*blobReader, error) {
	cmd := gitCommand(ctx, dir, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &blobReader{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 64<<10)}, nil
}

func (b *blobReader) close() {
	_ = b.in.Close()
	_ = b.cmd.Wait()
}

type blob struct {
	found bool   // a blob exists at the spec
	oid   string // its id
	data  []byte // its content, when asked for and within contentMaxBlobBytes
	big   bool   // content was asked for and is over contentMaxBlobBytes
}

// get asks for one object name and reads the answer in lockstep, so neither
// pipe can fill while the other side waits.
func (b *blobReader) get(spec string, wantData bool) (blob, error) {
	if _, err := io.WriteString(b.in, spec+"\n"); err != nil {
		return blob{}, err
	}
	line, err := b.out.ReadString('\n')
	if err != nil {
		return blob{}, err
	}
	line = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(line, " missing") {
		return blob{}, nil
	}
	f := strings.Fields(line)
	if len(f) != 3 {
		return blob{}, fmt.Errorf("git cat-file: unexpected answer %q", line)
	}
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return blob{}, fmt.Errorf("git cat-file: unexpected answer %q", line)
	}
	res := blob{oid: f[0], found: f[1] == "blob"}
	if res.found && wantData && size <= contentMaxBlobBytes {
		res.data = make([]byte, size)
		if _, err := io.ReadFull(b.out, res.data); err != nil {
			return blob{}, err
		}
		size = 0
	} else if res.found && wantData {
		res.big = true
	}
	if _, err := io.CopyN(io.Discard, b.out, size+1); err != nil {
		return blob{}, err
	}
	return res, nil
}

// contentCheck measures the branch against the default branch from base.
func (h *Hunter) contentCheck(ctx context.Context, rs *repoScan, dir, base string) mergeVerdict {
	unknown := mergeVerdict{state: mergedUnknown}
	changes, diffs, err := branchChanges(ctx, dir, base)
	if err != nil {
		return unknown
	}
	if len(changes) == 0 {
		return mergeVerdict{state: mergedEmpty}
	}
	ix, err := h.repoPaths(ctx, rs)
	if err != nil {
		return unknown
	}
	v, err := measureContent(ctx, dir, rs.def, ix, changes, diffs)
	if err != nil {
		return unknown
	}
	return v
}

// branchChanges reads the branch's changed files and what each adds.
func branchChanges(ctx context.Context, dir, base string) ([]change, []fileDiff, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	changes, err := readChanges(ctx, dir, base)
	if err != nil || len(changes) == 0 {
		return nil, nil, err
	}
	diffs, err := readPatch(ctx, dir, base, len(changes))
	if err != nil {
		return nil, nil, err
	}
	return changes, diffs, nil
}

// measureContent compares every change with the default branch.
func measureContent(ctx context.Context, dir, def string, ix *pathIndex, changes []change, diffs []fileDiff) (mergeVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	br, err := startBlobReader(ctx, dir)
	if err != nil {
		return mergeVerdict{}, err
	}
	defer br.close()

	// files caches each counterpart's lines; nil is "not there".
	files := map[string]*counterpart{}
	read := 0
	load := func(p string) (*counterpart, error) {
		if cp, ok := files[p]; ok {
			return cp, nil
		}
		b, err := br.get(def+":"+p, true)
		if err != nil {
			return nil, err
		}
		if read += len(b.data); b.big || read > contentMaxReadBytes {
			return nil, errContentBound
		}
		var cp *counterpart
		if b.found {
			cp = &counterpart{set: map[string]struct{}{}}
			for _, l := range strings.Split(string(b.data), "\n") {
				if l = normalizeLine(l); l != "" {
					if _, dup := cp.set[l]; !dup {
						cp.set[l] = struct{}{}
						cp.lines = append(cp.lines, l)
					}
				}
			}
		}
		files[p] = cp
		return cp, nil
	}

	type miss struct {
		line string
		in   []*counterpart
	}
	var res mergeVerdict
	var misses []miss
	contained := true
	for i, c := range changes {
		d := diffs[i]
		switch {
		case c.status == 'D':
			present := false
			if ix.big {
				b, err := br.get(def+":"+c.path, false)
				if err != nil {
					return mergeVerdict{}, err
				}
				present = b.found
			} else {
				present = ix.has(c.path)
			}
			if present {
				contained = false
			}
		case d.binary:
			cands, err := ix.counterparts(c.path)
			if err != nil {
				return mergeVerdict{}, err
			}
			same := false
			for _, q := range cands {
				b, err := br.get(def+":"+q, false)
				if err != nil {
					return mergeVerdict{}, err
				}
				same = same || (b.found && b.oid == c.oid)
			}
			if !same {
				contained = false
			}
		case len(d.added) > 0 || c.status == 'A':
			cands, err := ix.counterparts(c.path)
			if err != nil {
				return mergeVerdict{}, err
			}
			var cps []*counterpart
			for _, q := range cands {
				cp, err := load(q)
				if err != nil {
					return mergeVerdict{}, err
				}
				if cp != nil {
					cps = append(cps, cp)
				}
			}
			if len(cps) == 0 {
				contained = false
			}
			res.lines += len(d.added)
			for _, l := range d.added {
				found := false
				for _, cp := range cps {
					if _, ok := cp.set[l]; ok {
						found = true
						break
					}
				}
				if !found {
					misses = append(misses, miss{line: l, in: cps})
				}
			}
		}
	}
	// A line the default branch has only in a longer form (a list it
	// appended to, an import that gained names) still carries the branch's
	// work. Many such lines is a rewrite, not an extension; a long miss list
	// is not merged either way and is not searched.
	if len(misses) <= extendedMaxTries {
		for _, m := range misses {
			if extendedIn(m.line, m.in) {
				res.extended++
			}
		}
	}
	res.missing = len(misses) - res.extended
	res.state = mergedNo
	if contained && res.missing == 0 && res.extended <= max(extendedMinCap, res.lines/10) {
		res.state = mergedContent
	}
	return res, nil
}

// counterpart is one default-branch file's distinct non-blank lines; words
// holds each line's word set, built the first time an extended match needs it.
type counterpart struct {
	set   map[string]struct{}
	lines []string
	words []map[string]struct{}
}

// wordRE splits a line into the words an extended match compares.
var wordRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[0-9]+`)

// extendedIn reports whether a counterpart has a longer line holding every
// word of line, which needs at least extendedMinWords words.
func extendedIn(line string, cps []*counterpart) bool {
	want := wordRE.FindAllString(line, -1)
	if len(want) < extendedMinWords {
		return false
	}
	for _, cp := range cps {
		if cp.words == nil {
			cp.words = make([]map[string]struct{}, len(cp.lines))
			for i, l := range cp.lines {
				ws := map[string]struct{}{}
				for _, w := range wordRE.FindAllString(l, -1) {
					ws[w] = struct{}{}
				}
				cp.words[i] = ws
			}
		}
		for i, l := range cp.lines {
			if len(l) <= len(line) {
				continue
			}
			all := true
			for _, w := range want {
				if _, ok := cp.words[i][w]; !ok {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
	}
	return false
}
