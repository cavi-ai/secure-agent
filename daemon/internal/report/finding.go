package report

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

// categoryLabels: subject category → display label and its article.
var categoryLabels = map[string]struct{ label, article string }{
	sensitive.CatEnvFile.String():        {"environment file", "an"},
	sensitive.CatSSHKey.String():         {"SSH private key", "an"},
	sensitive.CatAWS.String():            {"AWS credentials", ""},
	sensitive.CatKeychain.String():       {"keychain", "a"},
	sensitive.CatKeychainSystem.String(): {"system trust store", "a"},
	sensitive.CatOther.String():          {"sensitive file", "a"},
	transcriptCategory:                   {"agent transcript", "an"},
}

const (
	transcriptCategory = "transcript"
	methodPost         = "POST"
)

// GuardRuleForCategory: subject category → the guard rule a per-path allow
// is recorded under.
var GuardRuleForCategory = map[string]string{
	sensitive.CatEnvFile.String():  "env-files",
	sensitive.CatSSHKey.String():   "ssh-keys",
	sensitive.CatAWS.String():      "cloud-creds",
	sensitive.CatKeychain.String(): "keychain",
}

// EvidenceOfKind is f's first evidence item of kind, nil when it has none.
func EvidenceOfKind(f model.Flag, kind string) *model.EvidenceItem {
	for i := range f.Evidence {
		if f.Evidence[i].Kind == kind {
			return &f.Evidence[i]
		}
	}
	return nil
}

// FirstNonEmpty is the first non-empty string in strs, or "".
func FirstNonEmpty(strs []string) string {
	for _, s := range strs {
		if s != "" {
			return s
		}
	}
	return ""
}

// ReaderName names the process that read the file ("gh", "claude-code
// 2.1.281"); empty when the read item names no executable or the reader is
// the agent itself.
func ReaderName(r *model.EvidenceItem, agent string) string {
	if r == nil || r.Exe == "" {
		return ""
	}
	name := agents.HarnessLabel(r.Exe)
	if agent != "" && strings.HasPrefix(strings.ToLower(name), strings.ToLower(agent)) {
		return ""
	}
	return name
}

// SubjectEvidence is the first evidence item naming a file: a read, a
// keychain access, a transcript, or a violation that carries a path.
func SubjectEvidence(evidence []model.EvidenceItem) *model.EvidenceItem {
	for i := range evidence {
		ev := &evidence[i]
		switch {
		case ev.Kind == "read" || ev.Kind == "keychain" || ev.Kind == "transcript":
			return ev
		case ev.Kind == "violation" && strings.HasPrefix(ev.Label, "/"):
			return ev
		}
	}
	return nil
}

// ExplainSubject describes the file an evidence item names.
func ExplainSubject(ev model.EvidenceItem, workspace, repo, home string) *model.ExplainSubject {
	var category string
	switch ev.Kind {
	case "transcript":
		category = transcriptCategory
	case "keychain":
		category = sensitive.CatKeychain.String()
	default:
		category = sensitive.CategoryForRule(ev.Rule).String()
	}
	return &model.ExplainSubject{
		Path:          ev.Label,
		Display:       DisplayPath(ev.Label, home),
		Basename:      filepath.Base(ev.Label),
		Category:      category,
		CategoryLabel: categoryLabels[category].label,
		Rule:          ev.Rule,
		OwnerLabel:    ownerLabel(ev.Label, workspace, repo, home),
	}
}

// DisplayPath abbreviates the home directory to ~ and middle-truncates to 64
// runes.
func DisplayPath(path, home string) string {
	d := path
	if home != "" && (path == home || strings.HasPrefix(path, home+"/")) {
		d = "~" + path[len(home):]
	}
	return middleTruncate(d, 64)
}

func middleTruncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	head := (max - 1) / 2
	tail := max - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

// ownerLabel names who a path belongs to: a harness's own config, the
// session's repo, a temp directory, the home directory, or the system.
func ownerLabel(path, workspace, repo, home string) string {
	under := func(dir string) bool {
		dir = strings.TrimRight(dir, "/")
		return dir != "" && (path == dir || strings.HasPrefix(path, dir+"/"))
	}
	switch {
	case home != "" && under(home+"/.claude/skills"):
		return "Claude skills (~/.claude/skills)"
	case home != "" && under(home+"/.claude"):
		return "Claude Code config (~/.claude)"
	case home != "" && under(home+"/.cursor"):
		return "Cursor config"
	case home != "" && under(home+"/.config/opencode"):
		return "opencode config"
	case repo != "" && under(workspace):
		return "repo " + repo
	case under(os.Getenv("TMPDIR")) || under("/var/folders") || under("/private/var/folders") || under("/tmp") || under("/private/tmp"):
		return "temp directory"
	case home != "" && under(home):
		return "home directory"
	default:
		return "system"
	}
}

// RepoName is the session's repo, else the workspace's name.
func RepoName(sess *model.Session, workspace string) string {
	if sess != nil && sess.Repo != "" {
		return sess.Repo
	}
	return posture.WorkspaceName(workspace)
}

// SplitHostPort splits a "host:port" evidence label (IPv6 hosts arrive
// unbracketed, so the port is after the last colon).
func SplitHostPort(label string) (string, int) {
	i := strings.LastIndex(label, ":")
	if i <= 0 {
		return label, 0
	}
	port, err := strconv.Atoi(label[i+1:])
	if err != nil {
		return label, 0
	}
	return strings.Trim(label[:i], "[]"), port
}

// ExplainWhat is the one-sentence account of the flag, from the rule's
// template. No pids; the destination's org over its address.
func ExplainWhat(f model.Flag, ex *model.FlagExplain, sess *model.Session) string {
	agent := "An agent"
	if f.Agent != "" {
		agent = posture.FamilyTitle(f.Agent)
	}
	dest := "an outside host"
	if len(ex.Egress) > 0 {
		dest = FirstNonEmpty([]string{ex.Egress[0].Org, ex.Egress[0].Host})
	}
	switch f.Rule {
	case "sensitive-read-then-connect":
		if reader := ReaderName(EvidenceOfKind(f, "read"), f.Agent); reader != "" {
			agent = reader + " (" + agent + ")"
		}
		what := agent + " read " + subjectPhrase(ex.Subject)
		if len(ex.Egress) == 0 {
			return what + " near an observed outside connection."
		}
		gap := ex.Egress[0].GapSeconds
		if gap < 0 {
			return what + ", " + gapPhrase(gap) + " after reaching " + dest + "."
		}
		return what + ", then reached " + dest + " " + gapPhrase(gap) + " later."
	case "keychain-access":
		if ex.Subject == nil {
			return agent + " opened a keychain file."
		}
		return agent + " opened " + ex.Subject.Basename + " in the keychain."
	case "keychain-security-cli":
		return agent + " ran the keychain tool."
	case "tcc-tamper":
		if label := evidenceLabel(f.Evidence, "tcc"); label != "" {
			return agent + " changed macOS privacy permissions (" + label + ")."
		}
		return agent + " changed macOS privacy permissions."
	case "launch-item-change":
		ev := EvidenceOfKind(f, "launch-item")
		switch {
		case ev == nil || ev.Label == "":
			return agent + " changed the background items that run after the agent exits."
		case ev.Sub == "background item removed":
			return agent + " removed a background item (" + filepath.Base(ev.Label) + ")."
		}
		return agent + " added a background item (" + filepath.Base(ev.Label) + ") that runs after the agent exits."
	case "trust-change":
		if label := evidenceLabel(f.Evidence, "profile"); label != "" {
			return agent + " installed a configuration profile (" + label + ")."
		}
		if label := evidenceLabel(f.Evidence, "gatekeeper"); label != "" {
			return agent + " overrode Gatekeeper for " + filepath.Base(label) + "."
		}
		return agent + " changed what macOS trusts."
	case "xprotect-detection":
		if ev := EvidenceOfKind(f, "malware"); ev != nil && ev.Label != "" {
			return "XProtect detected " + ev.Sub + " in " + filepath.Base(ev.Label) + "."
		}
		return "XProtect detected malware on this Mac."
	case "proxy-secret-leak":
		return agent + " sent " + secretPhrase(violationType(f.Evidence, "proxy-secret-leak")) + " to " + dest + "."
	case "proxy-prompt-injection":
		return "A response to " + agent + " from " + dest + " contained a prompt injection."
	case "proxy-inspection-incomplete":
		return "The proxy could not inspect the full request to " + dest + ". Its bounded scan or a body read failure left a coverage gap; the fail-open policy still applies."
	case "secret-in-transcript":
		harness := f.Agent
		if sess != nil && sess.Harness != "" {
			harness = sess.Harness
		}
		what := capitalize(secretPhrase(evidenceRule(f.Evidence, "transcript"))) + " appeared in " + article(posture.FamilyTitle(harness)) + " transcript"
		if ex.Subject != nil {
			what += " (" + ex.Subject.Basename + ")"
		}
		return what + "."
	case "untrusted-egress":
		return untrustedEgressWhat(f, agent)
	case "proxy-untrusted-egress":
		return "The proxy refused a connection from " + agent + " to " + dest + ": its session read untrusted content, and untrusted-egress is set to deny or the prompt was denied."
	case "proxy-untrusted-egress-monitored":
		return "The proxy let a connection from " + agent + " to " + dest + " through after its session read untrusted content: untrusted-egress is set to monitor."
	default:
		return posture.HumanFlagTitle(f.Rule)
	}
}

// untrustedInputPhrases: an input kind as the object of "read".
var untrustedInputPhrases = map[string]string{
	"image":        "an image",
	"web":          "a web page",
	"search":       "web search results",
	"mcp":          "MCP tool output",
	"fetch":        "downloaded content",
	"gh":           "GitHub content",
	"instructions": "an instruction file",
	"injection":    "an injection in tool output",
}

// untrustedEgressWhat: "<agent> read an image (x.png), then sent data out
// through curl host. It ran; monitor mode records it."
func untrustedEgressWhat(f model.Flag, agent string) string {
	var inputs []string
	sink, decision := "", ""
	for _, ev := range f.Evidence {
		switch ev.Kind {
		case "untrusted-input":
			where := strings.TrimPrefix(ev.Label, model.UntrustedKindLabel(ev.Rule)+": ")
			if ev.Rule == "image" || ev.Rule == "instructions" {
				where = filepath.Base(where)
			}
			phrase, ok := untrustedInputPhrases[ev.Rule]
			if !ok {
				phrase = "untrusted content"
			}
			inputs = append(inputs, phrase+" ("+middleTruncate(where, 64)+")")
		case "send":
			sink, decision = ev.Label, ev.Sub
		}
	}
	read := "untrusted content"
	switch len(inputs) {
	case 0:
	case 1:
		read = inputs[0]
	case 2:
		read = inputs[0] + " and 1 more untrusted input"
	default:
		read = fmt.Sprintf("%s and %d more untrusted inputs", inputs[0], len(inputs)-1)
	}
	what := agent + " read " + read + ", then sent data out"
	if sink != "" {
		what += " through " + sink
	}
	what += "."
	if decision != "" {
		what += " Guard: " + decision + "."
	}
	return what
}

func subjectPhrase(s *model.ExplainSubject) string {
	if s == nil {
		return "a sensitive file"
	}
	cl := categoryLabels[s.Category]
	label := s.CategoryLabel
	if cl.article != "" {
		label = cl.article + " " + label
	}
	return label + " in " + ownerPhrase(s.OwnerLabel)
}

// ownerPhrase fits a generic owner label into a sentence.
func ownerPhrase(owner string) string {
	switch owner {
	case "home directory":
		return "your home directory"
	case "temp directory":
		return "a temp directory"
	case "system":
		return "a system location"
	default:
		return owner
	}
}

// gapPhrase renders a read→connect gap: "3 s", "2 min", "1 h".
func gapPhrase(seconds float64) string {
	s := int(math.Round(math.Abs(seconds)))
	switch {
	case s < 1:
		return "moments"
	case s < 60:
		return fmt.Sprintf("%d s", s)
	case s < 3600:
		return fmt.Sprintf("%d min", int(math.Round(float64(s)/60)))
	default:
		return fmt.Sprintf("%d h", int(math.Round(float64(s)/3600)))
	}
}

func secretPhrase(kind string) string {
	if kind == "" {
		return "a secret"
	}
	return "a secret (" + kind + ")"
}

// violationType is the detail after "<rule>:" on the first violation item.
func violationType(evidence []model.EvidenceItem, rule string) string {
	label := evidenceLabel(evidence, "violation")
	if rest, ok := strings.CutPrefix(label, rule); ok {
		return strings.TrimPrefix(rest, ":")
	}
	return label
}

func evidenceLabel(evidence []model.EvidenceItem, kind string) string {
	for _, ev := range evidence {
		if ev.Kind == kind {
			return ev.Label
		}
	}
	return ""
}

func evidenceRule(evidence []model.EvidenceItem, kind string) string {
	for _, ev := range evidence {
		if ev.Kind == kind {
			return ev.Rule
		}
	}
	return ""
}

func article(word string) string {
	if word != "" && strings.ContainsRune("AEIOUaeiou", rune(word[0])) {
		return "an " + word
	}
	return "a " + word
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ValidMuteHost is the host shape POST /mute accepts: a bare hostname (no
// port, path, userinfo — so no IPv6 literal either).
func ValidMuteHost(host string) bool {
	return host != "" && !strings.ContainsAny(host, "/:@") && len(host) <= 253
}

// muteAgentRE bounds a mute's agent: a configured agent name or an
// "untagged:<exe>" label ("untagged:claude 2.1.280").
var muteAgentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_. :-]{0,127}$`)

// ValidMuteAgent accepts empty (every agent) or a bounded agent label.
func ValidMuteAgent(agent string) bool {
	return agent == "" || muteAgentRE.MatchString(agent)
}

// muteClassNoun names a rule class in a mute label ("Mute keychain access
// for codex").
var muteClassNoun = map[string]string{
	"keychain-access":       "keychain access",
	"keychain-security-cli": "keychain tool runs",
}

// MuteRuleHostAction is the served mute-rule-host request for rule at host.
// An agent scopes the mute to that agent and the label names it; no agent
// mutes every agent. False for an agent POST /mute cannot scope to, so the
// served mute never widens to every agent.
func MuteRuleHostAction(rule, title, host, agent string) (model.ExplainAction, bool) {
	if !ValidMuteAgent(agent) {
		return model.ExplainAction{}, false
	}
	label, who := "Stop flagging this for "+host, ""
	body := map[string]any{"rule": rule, "host": host}
	if agent != "" {
		label, who = "Stop flagging this for "+host+" from "+agent, " from "+agent
		body["agent"] = agent
	}
	return model.ExplainAction{
		ID: "mute-rule-host", Label: label,
		Consequence: "\"" + title + "\" stops being flagged for " + host + who + "; the host stays monitored and its open flags of this rule are marked reviewed.",
		Method:      methodPost, Path: "/mute",
		Body: body,
	}, true
}

// MuteClassAction is the served mute-class request for a keychain rule;
// false for any other rule. Agent scoping as MuteRuleHostAction.
func MuteClassAction(rule, title, agent string) (model.ExplainAction, bool) {
	noun := muteClassNoun[rule]
	if noun == "" || !ValidMuteAgent(agent) {
		return model.ExplainAction{}, false
	}
	label, scope := "Dismiss this flag class", "for every agent"
	body := map[string]any{"rule": rule, "host": "*"}
	if agent != "" {
		label, scope = "Mute "+noun+" for "+agent, "for "+agent+"; other agents still flag"
		body["agent"] = agent
	}
	return model.ExplainAction{
		ID: "mute-class", Label: label,
		Consequence: "\"" + title + "\" stops raising flags " + scope + "; monitoring continues and suppressed hits are counted.",
		Method:      methodPost, Path: "/mute",
		Body: body,
	}, true
}

// MuteAgentSuffix is " (agent X)" for an agent-scoped mute, "" otherwise.
func MuteAgentSuffix(agent string) string {
	if agent == "" {
		return ""
	}
	return " (agent " + agent + ")"
}

// AllowHostLabel is the served allow-host button text. An IPv6 literal never
// appears in it — the popover and web console (web_dist/lib.js
// explainActionLabel) both drop it in favor of "this <Org> address" — while
// a hostname or IPv4 host keeps the readable "Allow <name> for <agent>" form.
func AllowHostLabel(name, host, org, agent string) string {
	if strings.Contains(host, ":") {
		if org != "" {
			return "Allow this " + org + " address for " + agent
		}
		return "Allow this address for " + agent
	}
	return "Allow " + name + " for " + agent
}

// recommendedFor maps the advisor's normalized suggested_action onto action
// ids, most specific first.
var recommendedFor = map[string][]string{
	"allow-host":         {"allow-host"},
	"mute-rule":          {"mute-rule-host", "mute-class"},
	"kill-agent":         {"kill"},
	"rotate-credentials": {"open-incident"},
}

// MarkRecommended flags the action the advisor's verdict suggested.
func MarkRecommended(acts []model.ExplainAction, v *model.AdvisorVerdict) {
	if v == nil {
		return
	}
	for _, id := range recommendedFor[v.SuggestedAction] {
		for i := range acts {
			if acts[i].ID == id {
				acts[i].Recommended = true
				return
			}
		}
	}
}
