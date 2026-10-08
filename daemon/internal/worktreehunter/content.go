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

// The content check measures similarity when neither ancestry nor a patch id
// proves a merge. It compares added/removed line counts, binary blobs, deleted
// files and modes, including renamed files and rewritten history. Text order
// and behavior are not established: even a full match is review evidence only.
// Anything the check cannot measure inside its bounds is unknown.

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
	other     int  // removed lines or files, binaries and modes that differ
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

// fileDiff is what the zero-context patch says about one changed file; the
// lines themselves are compared from the blobs.
type fileDiff struct {
	binary bool
}

// readPatch parses the branch's combined diff into one fileDiff per change,
// in the order `diff --raw` lists them, and enforces the added-line bound.
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
		case inHunk && strings.HasPrefix(line, "+") && normalizeLine(line[1:]) != "":
			if total++; total > contentMaxLines {
				return nil, errContentBound
			}
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
// trailing path, which must include a directory: a file name alone
// (README.md, .gitignore) says nothing about where the work went. More than
// contentMaxTies equally good ones is a bound.
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
	if best < 2 {
		return nil, nil
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
	v, err := measureContent(ctx, dir, base, rs.def, ix, changes, diffs)
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

// measureContent compares every change with the default branch. A text file
// is compared by line counts: every line the branch adds (net of the base)
// must be on the default branch at least as many times, and every line it
// removes must be there no more often than at the branch tip. A missing
// added line still counts when the default branch has it in a longer form
// (matchLongerForms). A deleted file must be gone, a binary must be the same
// blob and a changed file mode must match.
func measureContent(ctx context.Context, dir, base, def string, ix *pathIndex, changes []change, diffs []fileDiff) (mergeVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	br, err := startBlobReader(ctx, dir)
	if err != nil {
		return mergeVerdict{}, err
	}
	defer br.close()

	read := 0
	text := func(spec string) (lineCounts, bool, error) {
		b, err := br.get(spec, true)
		if err != nil {
			return lineCounts{}, false, err
		}
		if read += len(b.data); b.big || read > contentMaxReadBytes {
			return lineCounts{}, false, errContentBound
		}
		if !b.found {
			return lineCounts{}, false, nil
		}
		return countLines(b.data), true, nil
	}
	// files caches each counterpart's lines; nil is "not there".
	files := map[string]*lineCounts{}
	load := func(p string) (*lineCounts, error) {
		if lc, ok := files[p]; ok {
			return lc, nil
		}
		lc, found, err := text(def + ":" + p)
		if err != nil {
			return nil, err
		}
		var out *lineCounts
		if found {
			out = &lc
		}
		files[p] = out
		return out, nil
	}

	var res mergeVerdict
	var misses []miss
	var modes []modeChange
	contained := true
	for i, c := range changes {
		if c.status == 'D' {
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
				res.other++
			}
			continue
		}
		cands, err := ix.counterparts(c.path)
		if err != nil {
			return mergeVerdict{}, err
		}
		if c.status == 'M' && c.oldMode != c.newMode {
			modes = append(modes, modeChange{mode: c.newMode, paths: cands})
		}
		if diffs[i].binary {
			same := false
			for _, q := range cands {
				b, err := br.get(def+":"+q, false)
				if err != nil {
					return mergeVerdict{}, err
				}
				same = same || (b.found && b.oid == c.oid)
			}
			if !same {
				res.other++
			}
			continue
		}
		var cps []*lineCounts
		for _, q := range cands {
			lc, err := load(q)
			if err != nil {
				return mergeVerdict{}, err
			}
			if lc != nil {
				cps = append(cps, lc)
			}
		}
		if len(cps) == 0 {
			contained = false
		}
		head, _, err := text(c.oid)
		if err != nil {
			return mergeVerdict{}, err
		}
		var before lineCounts
		if c.status == 'M' {
			if before, _, err = text(base + ":" + c.path); err != nil {
				return mergeVerdict{}, err
			}
		}
		onMain := func(l string) int {
			n := 0
			for _, lc := range cps {
				n = max(n, lc.n[l])
			}
			return n
		}
		for _, l := range head.order {
			added := head.n[l] - before.n[l]
			if added <= 0 {
				continue
			}
			res.lines += added
			if have := onMain(l); have < added {
				misses = append(misses, miss{line: l, n: added - have, in: cps, base: before})
			}
		}
		// A removed line the default branch still has more often than the
		// branch tip is a removal that never landed. Lines without a word
		// ("}", "*/") say nothing about where they went.
		for _, l := range before.order {
			if head.n[l] < before.n[l] && wordRE.MatchString(l) && onMain(l) > head.n[l] {
				res.other++
			}
		}
	}
	if len(modes) > 0 {
		n, err := modesDiffering(ctx, dir, def, modes)
		if err != nil {
			return mergeVerdict{}, err
		}
		res.other += n
	}
	if err := matchLongerForms(ctx, misses, &res); err != nil {
		return mergeVerdict{}, err
	}
	res.state = mergedNo
	if contained && res.missing == 0 && res.other == 0 && res.extended <= max(extendedMinCap, res.lines/10) {
		res.state = contentSimilar
	}
	return res, nil
}

// lineCounts is a file's non-blank lines, trailing whitespace dropped: how
// many times each occurs, and each distinct line in file order.
type lineCounts struct {
	n     map[string]int
	order []string
}

func countLines(data []byte) lineCounts {
	lc := lineCounts{n: map[string]int{}}
	for _, l := range strings.Split(string(data), "\n") {
		if l = normalizeLine(l); l != "" {
			if lc.n[l] == 0 {
				lc.order = append(lc.order, l)
			}
			lc.n[l]++
		}
	}
	return lc
}

// miss is an added line the default branch lacks n times, with the files
// that stand in for it there and the branch file's base.
type miss struct {
	line string
	n    int
	in   []*lineCounts
	base lineCounts
}

// modeChange is a file whose mode the branch changed and the default-branch
// paths that stand in for it.
type modeChange struct {
	mode  string
	paths []string
}

// modesDiffering counts the mode changes no stand-in on def carries.
func modesDiffering(ctx context.Context, dir, def string, changes []modeChange) (int, error) {
	var paths []string
	for _, m := range changes {
		paths = append(paths, m.paths...)
	}
	modes := map[string]string{}
	if len(paths) > 0 {
		args := append([]string{"--literal-pathspecs", "ls-tree", "-z", "--full-tree", def, "--"}, paths...)
		out, err := gitLimited(ctx, dir, contentMaxRawBytes, args...)
		if err != nil {
			return 0, err
		}
		for _, rec := range strings.Split(out, "\x00") {
			meta, p, ok := strings.Cut(rec, "\t")
			if f := strings.Fields(meta); ok && len(f) == 3 {
				modes[p] = f[0]
			}
		}
	}
	n := 0
	for _, m := range changes {
		same := false
		for _, p := range m.paths {
			same = same || modes[p] == m.mode
		}
		if !same {
			n++
		}
	}
	return n, nil
}

// wordRE splits a line into the words a longer-form match compares.
var wordRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[0-9]+`)

// extendedMaxWork bounds the line comparisons one check spends on longer
// forms (a variable so a test can lower it); past it, the rest stay missing.
var extendedMaxWork = 5_000_000

// matchLongerForms counts each miss as extended when the default branch has
// it in a longer form (a list it appended to, an import that gained names),
// else as missing. More than extendedMaxTries misses are not searched: that
// many is not merged either way.
func matchLongerForms(ctx context.Context, misses []miss, res *mergeVerdict) error {
	work := 0
	for _, m := range misses {
		found := false
		if len(misses) <= extendedMaxTries {
			var err error
			if found, err = longerFormIn(ctx, m, &work); err != nil {
				return err
			}
		}
		if found {
			res.extended += m.n
		} else {
			res.missing += m.n
		}
	}
	return nil
}

// longerFormIn reports whether a stand-in has a longer line holding every
// word of the missed line. The line needs extendedMinWords words, and a
// longer line the base already had is the branch's own pre-image (the line
// it shortened or rewrote), never an extension.
func longerFormIn(ctx context.Context, m miss, work *int) (bool, error) {
	want := wordRE.FindAllString(m.line, -1)
	if len(want) < extendedMinWords {
		return false, nil
	}
	key := want[0]
	for _, w := range want[1:] {
		if len(w) > len(key) {
			key = w
		}
	}
	for _, lc := range m.in {
		for _, l := range lc.order {
			if *work++; *work > extendedMaxWork {
				return false, nil
			}
			if *work%4096 == 0 {
				if err := ctx.Err(); err != nil {
					return false, err
				}
			}
			if len(l) <= len(m.line) || m.base.n[l] > 0 || !strings.Contains(l, key) {
				continue
			}
			have := map[string]bool{}
			for _, w := range wordRE.FindAllString(l, -1) {
				have[w] = true
			}
			all := true
			for _, w := range want {
				if !have[w] {
					all = false
					break
				}
			}
			if all {
				return true, nil
			}
		}
	}
	return false, nil
}
