package agents

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
)

// argv0Source is a ProcSource that can read a process's argv[0].
type argv0Source interface {
	Argv0(pid int32) string
}

var (
	versionSegRE = regexp.MustCompile(`^v?\d+(\.\d+)+([-+][0-9A-Za-z.]+)?$`)
	// envAssignRE finds where an overwritten process title spills into the
	// environment block ("… KEY=value"): argv[0] is cut there.
	envAssignRE = regexp.MustCompile(`\s+[A-Za-z_][A-Za-z0-9_]*=`)
)

const maxArgv0 = 128

// Snapshot describes pid for a flag: exe, name, argv[0] (scrubbed, never
// the rest of argv or the environment), parent, and the launcher — the
// nearest app bundle above the harness root, then the harness root itself.
func (t *Tagger) Snapshot(pid int32) (model.FlagProcess, bool) {
	if pid <= 0 {
		return model.FlagProcess{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.procLocked(pid)
	if !ok || (p.Exe == "" && p.Comm == "") {
		return model.FlagProcess{}, false
	}
	out := model.FlagProcess{Exe: p.Exe, PPID: p.PPID}
	if src, ok := t.ps.(argv0Source); ok {
		out.Args0 = SanitizeArgv0(src.Argv0(pid))
	}
	out.Name = processName(p, out.Args0)

	var harness string
	from := p.PPID
	if info, ok := t.cache[pid]; ok && t.tagged[pid] && info.RootPID > 0 {
		if root, ok := t.procLocked(info.RootPID); ok && root.Exe != "" {
			harness = HarnessLabel(root.Exe)
			from = root.PPID
		}
	}
	var bundle string
	seen := map[int32]bool{}
	for hops := 0; hops < 32 && from > 1 && !seen[from]; hops++ {
		seen[from] = true
		q, ok := t.procLocked(from)
		if !ok {
			break
		}
		if b := appBundle(q.Exe); b != "" {
			bundle = b
			break
		}
		from = q.PPID
	}
	var parts []string
	if bundle != "" && bundle != harness {
		parts = append(parts, bundle)
	}
	if harness != "" {
		parts = append(parts, harness)
	}
	out.Launcher = strings.Join(parts, " › ")
	return out, true
}

// SanitizeArgv0 keeps argv[0] up to an environment spill-over, capped and
// with secret-shaped values scrubbed.
func SanitizeArgv0(s string) string {
	if loc := envAssignRE.FindStringIndex(s); loc != nil {
		s = s[:loc[0]]
	}
	s = strings.TrimSpace(s)
	if len(s) > maxArgv0 {
		s = s[:maxArgv0]
	}
	return redact.Scrub(s)
}

// processName: the exe's base name; argv[0]'s when the exe is a bare version
// file (~/.local/share/claude/versions/2.1.281); comm when neither is known.
func processName(p ProcInfo, args0 string) string {
	name := filepath.Base(p.Exe)
	if p.Exe == "" {
		name = p.Comm
	}
	if versionSegRE.MatchString(name) && args0 != "" {
		name = filepath.Base(args0)
	}
	return name
}

// HarnessLabel names a harness root by its exe: "<dir> <version>" when the
// path carries a version directory (".../claude-code/2.1.281/claude.app/…"
// → "claude-code 2.1.281"), else its app bundle, else its base name.
func HarnessLabel(exe string) string {
	segs := strings.Split(filepath.ToSlash(exe), "/")
	for i := len(segs) - 1; i > 0; i-- {
		if !versionSegRE.MatchString(segs[i]) {
			continue
		}
		prev := i - 1
		if segs[prev] == "versions" && prev > 0 {
			prev--
		}
		if segs[prev] != "" {
			return segs[prev] + " " + segs[i]
		}
	}
	if b := appBundle(exe); b != "" {
		return b
	}
	return filepath.Base(exe)
}

// appBundle is the outermost "*.app" directory on exe's path, or "".
func appBundle(exe string) string {
	for _, seg := range strings.Split(filepath.ToSlash(exe), "/") {
		if strings.HasSuffix(seg, ".app") && len(seg) > len(".app") {
			return seg
		}
	}
	return ""
}
