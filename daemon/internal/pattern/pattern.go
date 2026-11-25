// Package pattern words and groups repeated findings: a pattern's subject,
// cadence, process lists and summary, and the parts of routine read groups.
package pattern

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/report"
)

// BurstGap is the largest gap between consecutive flags that counts as a burst.
const BurstGap = 5 * time.Second

// Subject is the served subject of f and the text that keys it: the
// file the explanation names (display path; the absolute path keys it), else
// the first destination host, else nothing.
func Subject(f model.Flag, home string) (model.EvidenceItem, string) {
	if ev := report.SubjectEvidence(f.Evidence); ev != nil {
		s := report.ExplainSubject(*ev, f.Workspace, "", home)
		return model.EvidenceItem{Kind: ev.Kind, Label: s.Display, Sub: s.CategoryLabel}, s.Path
	}
	for _, ev := range f.Evidence {
		if ev.Kind != "connect" || ev.Label == "" {
			continue
		}
		if host, _ := report.SplitHostPort(ev.Label); host != "" {
			return model.EvidenceItem{Kind: "connect", Label: host, Sub: hostid.IdentifyCached(host).Org}, host
		}
	}
	return model.EvidenceItem{}, ""
}

// Processes groups the flags' process snapshots by name and
// launcher, counting distinct pids; busiest PatternListCap first. Never nil.
func Processes(flags []model.Flag) []model.PatternProcess {
	type procKey struct{ name, launcher string }
	pids := map[procKey]map[int32]bool{}
	for _, f := range flags {
		if f.Process == nil || f.Process.Name == "" {
			continue
		}
		k := procKey{f.Process.Name, f.Process.Launcher}
		if pids[k] == nil {
			pids[k] = map[int32]bool{}
		}
		pids[k][f.PID] = true
	}
	out := make([]model.PatternProcess, 0, len(pids))
	for k, set := range pids {
		out = append(out, model.PatternProcess{Name: k.name, Launcher: k.launcher, Count: len(set)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Launcher < out[j].Launcher
	})
	return CapList(out, model.PatternListCap)
}

// DispositionRank orders open dispositions: critical > warning > benign-likely.
func DispositionRank(state string) int {
	switch state {
	case model.DispositionCritical:
		return 3
	case model.DispositionWarning:
		return 2
	case model.DispositionBenignLikely:
		return 1
	}
	return 0
}

// Median is the middle value of values (the mean of the two middle ones for
// an even count), 0 for none.
func Median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	s := append([]float64(nil), values...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// Busiest lists the most frequent keys first (ties by key), at most
// model.PatternListCap.
func Busiest[K int32 | string](counts map[K]int) []K {
	keys := make([]K, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return CapList(keys, model.PatternListCap)
}

// CapList is list truncated to its first n entries.
func CapList[T any](list []T, n int) []T {
	if len(list) > n {
		return list[:n]
	}
	return list
}

// CadencePhrase reads the median gap between consecutive flags.
func CadencePhrase(medianS float64, gaps int) string {
	every := func(n int, unit string) string {
		if n <= 1 {
			return "about every " + unit
		}
		return fmt.Sprintf("about every %d %ss", n, unit)
	}
	switch {
	case gaps == 0:
		return "once"
	case medianS < 1:
		return "in bursts under a second apart"
	case medianS < BurstGap.Seconds():
		return "in bursts a few seconds apart"
	case medianS < 90:
		return every(int(math.Round(medianS)), "second")
	case medianS < 90*60:
		return every(int(math.Round(medianS/60)), "minute")
	default:
		return every(int(math.Round(medianS/3600)), "hour")
	}
}

// patternVerb is the rule's action phrase from the rule-title table's
// vocabulary: "<agent> <verb> <n> times".
func patternVerb(rule string, subject model.EvidenceItem) string {
	host := ""
	if subject.Kind == "connect" {
		host = subject.Label
	}
	switch rule {
	case "keychain-access":
		return "touched the " + keychainName(subject.Label)
	case "keychain-security-cli":
		return "ran the macOS keychain tool"
	case "tcc-tamper":
		return "changed macOS privacy permissions"
	case "launch-item-change":
		return "changed a background item"
	case "trust-change":
		return "changed what macOS trusts"
	case "xprotect-detection":
		return "detected malware"
	case "sensitive-read-then-connect":
		if subject.Label != "" && host == "" {
			return "read " + subject.Label + " and connected out"
		}
		return "read a secret and connected out"
	case "proxy-secret-leak":
		return "sent a secret to " + report.FirstNonEmpty([]string{host, "an outside host"})
	case "proxy-prompt-injection":
		return "received a prompt injection from " + report.FirstNonEmpty([]string{host, "an outside host"})
	case "secret-in-transcript":
		return "wrote a secret into its transcript"
	default:
		return "raised \"" + posture.HumanFlagTitle(rule) + "\""
	}
}

// keychainName: ".../login.keychain-db" → "login keychain".
func keychainName(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".keychain-db"), ".keychain")
	if path == "" || name == "" || name == "." || name == "/" {
		return "keychain"
	}
	return name + " keychain"
}

// patternWindow: "between 03:00 and 03:08" (local time), with the date when
// the window is not today or spans days.
func patternWindow(first, last, now time.Time) string {
	f, l := first.Local(), last.Local()
	day := func(t time.Time) string { return t.Format("2006-01-02") }
	switch {
	case day(f) != day(l):
		return "between " + f.Format("Jan 2 15:04") + " and " + l.Format("Jan 2 15:04")
	case day(l) != day(now.Local()):
		return "on " + f.Format("Jan 2") + " between " + f.Format("15:04") + " and " + l.Format("15:04")
	default:
		return "between " + f.Format("15:04") + " and " + l.Format("15:04")
	}
}

// Summary is the one served sentence: who did what how many times,
// when, from how many processes and sessions, and how often. No flag ids.
func Summary(p model.Pattern, now time.Time, reader string) string {
	var ident []string
	if p.PIDCount > 0 {
		noun := "processes"
		if p.PIDCount == 1 {
			noun = "process"
		}
		ident = append(ident, fmt.Sprintf("%d %s", p.PIDCount, noun))
	}
	if p.SessionCount > 0 {
		ident = append(ident, fmt.Sprintf("%d session%s", p.SessionCount, Plural(p.SessionCount)))
	}
	who := report.FirstNonEmpty([]string{p.Agent, "An agent"})
	verb := patternVerb(p.Rule, p.Subject)
	if p.Rule == posture.ReadConnectRule {
		// "gh (claude) read ~/.config/gh/hosts.yml, then reached GitHub (…)"
		if reader != "" {
			who = reader + " (" + who + ")"
		}
		verb = "read " + report.FirstNonEmpty([]string{p.Subject.Label, "a secret"}) + " near connections to " + destinationPhrase(p.Destinations)
	}
	s := fmt.Sprintf("%s %s %d times %s", who, verb, p.Count, patternWindow(p.First, p.Last, now))
	if len(ident) > 0 {
		s += " (" + strings.Join(ident, ", ") + ")"
	}
	return s + ", " + p.Cadence + "."
}

// ActionIndex is the index of the action with id in acts, -1 when absent.
func ActionIndex(acts []model.ExplainAction, id string) int {
	for i := range acts {
		if acts[i].ID == id {
			return i
		}
	}
	return -1
}

// Plural is the "s" suffix for a count other than one.
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
