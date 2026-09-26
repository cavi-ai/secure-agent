package sysagent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Harness is a coding agent the system agent can dispatch work to, always
// run against the local Ollama.
type Harness struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Bin   string `json:"bin"`
	// MinOllama is the oldest Ollama whose API the harness needs; "" when
	// any release that serves the model works.
	MinOllama string `json:"min_ollama,omitempty"`
}

// Harnesses in the order the console lists them. Claude Code needs Ollama's
// Anthropic Messages API (0.14.0); Codex needs its Responses API (0.13.4).
var Harnesses = []Harness{
	{ID: "claude", Label: "Claude Code", Bin: "claude", MinOllama: "0.14.0"},
	{ID: "codex", Label: "Codex", Bin: "codex", MinOllama: "0.13.4"},
	{ID: "openclaw", Label: "OpenClaw", Bin: "openclaw"},
	{ID: "hermes", Label: "Hermes Agent", Bin: "hermes"},
}

// Dispatch modes.
const (
	ModeHeadless = "headless"
	ModeTerminal = "terminal"
)

func harnessByID(id string) (Harness, bool) {
	for _, h := range Harnesses {
		if h.ID == id {
			return h, true
		}
	}
	return Harness{}, false
}

// launchSpec is what one dispatch is built from.
type launchSpec struct {
	Endpoint string // Ollama base URL, no /v1
	Model    string
	Workdir  string
	Task     string
	// StateDir holds the files a launch writes (pinned harness config, the
	// Codex answer file); Tag keeps one dispatch's files apart from
	// another's.
	StateDir   string
	Tag        string
	TimeoutSec int
}

// launch is how one harness run starts: its arguments, the variables set on
// top of the daemon's environment and the ones removed, and files written
// (mode 0600) before it runs.
type launch struct {
	Args  []string
	Env   []string // KEY=VALUE
	Unset []string
	Files map[string][]byte
	// AnswerFile is where Codex writes its last message (headless).
	AnswerFile string
}

// buildLaunch returns the launch of harness id in mode. Every recipe points
// the harness at sp.Endpoint and keeps its own permission model on: no
// recipe bypasses approvals or the sandbox.
//
//   - claude: Anthropic Messages API on Ollama. --settings carries the same
//     environment so a user settings file cannot route it elsewhere; web
//     tools are off (they reach Anthropic). Headless accepts file edits and
//     denies other shell commands.
//   - codex: the built-in ollama provider (--oss). Headless and terminal
//     runs are sandboxed to the folder with no network.
//   - openclaw: a config pinned by secure-agent (OPENCLAW_CONFIG_PATH) whose
//     only provider is the local Ollama. Host commands: denied headless,
//     asked in a terminal.
//   - hermes: the custom provider at CUSTOM_BASE_URL; writes kept inside the
//     folder (HERMES_WRITE_SAFE_ROOT). One-shot runs deny dangerous commands.
func buildLaunch(id, mode string, sp launchSpec) (launch, error) {
	if mode != ModeHeadless && mode != ModeTerminal {
		return launch{}, fmt.Errorf("unknown mode %q", mode)
	}
	headless := mode == ModeHeadless
	base := strings.TrimSuffix(sp.Endpoint, "/")
	noProxy := "NO_PROXY=127.0.0.1,localhost,::1"
	switch id {
	case "claude":
		env := map[string]string{
			"ANTHROPIC_BASE_URL":                                   base,
			"ANTHROPIC_AUTH_TOKEN":                                 "ollama",
			"ANTHROPIC_API_KEY":                                    "",
			"ANTHROPIC_MODEL":                                      sp.Model,
			"ANTHROPIC_DEFAULT_OPUS_MODEL":                         sp.Model,
			"ANTHROPIC_DEFAULT_SONNET_MODEL":                       sp.Model,
			"ANTHROPIC_DEFAULT_HAIKU_MODEL":                        sp.Model,
			"CLAUDE_CODE_SUBAGENT_MODEL":                           sp.Model,
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":             "1",
			"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
			"DISABLE_TELEMETRY":                                    "1",
			"DISABLE_ERROR_REPORTING":                              "1",
			"DISABLE_AUTOUPDATER":                                  "1",
		}
		settings, _ := json.Marshal(map[string]any{"env": env})
		l := launch{
			Env:   append(envPairs(env), noProxy),
			Unset: []string{"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"},
			Args:  []string{"--model", sp.Model, "--disallowedTools", "WebFetch,WebSearch", "--settings", string(settings)},
		}
		if headless {
			l.Args = append(l.Args, "--permission-mode", "acceptEdits", "--output-format", "json", "-p", sp.Task)
		} else {
			l.Args = append(l.Args, sp.Task)
		}
		return l, nil
	case "codex":
		l := launch{Env: []string{"CODEX_OSS_BASE_URL=" + base + "/v1", noProxy}}
		common := []string{"--oss", "--local-provider", "ollama", "-m", sp.Model, "--sandbox", "workspace-write"}
		if headless {
			l.AnswerFile = filepath.Join(sp.StateDir, "codex-answer-"+sp.Tag+".txt")
			l.Args = append(append([]string{"exec"}, common...), "--skip-git-repo-check", "-o", l.AnswerFile, sp.Task)
		} else {
			l.Args = append(common, "--ask-for-approval", "on-request", sp.Task)
		}
		return l, nil
	case "openclaw":
		execMode := "ask"
		if headless {
			execMode = "deny"
		}
		cfg, _ := json.MarshalIndent(map[string]any{
			"models": map[string]any{"providers": map[string]any{"ollama": map[string]any{
				"baseUrl": base, "apiKey": "ollama-local", "api": "ollama",
				"models": []map[string]string{{"id": sp.Model, "name": sp.Model}},
			}}},
			"agents": map[string]any{"defaults": map[string]any{"model": map[string]any{"primary": "ollama/" + sp.Model}}},
			"tools":  map[string]any{"exec": map[string]any{"mode": execMode}},
			"update": map[string]any{"checkOnStart": false},
		}, "", "  ")
		path := filepath.Join(sp.StateDir, "openclaw-"+sp.Tag+".json")
		l := launch{
			Env:   []string{"OPENCLAW_CONFIG_PATH=" + path, "OPENCLAW_NO_AUTO_UPDATE=1", "OPENCLAW_DISABLE_BONJOUR=1", noProxy},
			Files: map[string][]byte{path: cfg},
		}
		if headless {
			l.Args = []string{"agent", "exec", sp.Task, "--model", "ollama/" + sp.Model, "--cwd", sp.Workdir,
				"--timeout", strconv.Itoa(sp.TimeoutSec)}
		} else {
			l.Args = []string{"chat", "--message", sp.Task}
		}
		return l, nil
	case "hermes":
		l := launch{
			Env:   []string{"CUSTOM_BASE_URL=" + base + "/v1", "HERMES_WRITE_SAFE_ROOT=" + sp.Workdir, noProxy},
			Unset: []string{"HERMES_YOLO_MODE", "HERMES_INFERENCE_MODEL"},
		}
		if headless {
			l.Args = []string{"-z", sp.Task, "--provider", "custom", "-m", sp.Model}
		} else {
			l.Args = []string{"chat", "--provider", "custom", "-m", sp.Model, "-q", sp.Task}
		}
		return l, nil
	}
	return launch{}, fmt.Errorf("unknown harness %q", id)
}

// envPairs renders env as sorted KEY=VALUE pairs.
func envPairs(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// mergeEnv applies set and unset to base: a key in either replaces or
// drops base's value; NO_PROXY keeps base's entries after the loopback
// hosts.
func mergeEnv(base, set, unset []string) []string {
	drop := map[string]bool{}
	for _, k := range unset {
		drop[k] = true
	}
	setKeys := map[string]string{}
	for _, kv := range set {
		k, v, _ := strings.Cut(kv, "=")
		setKeys[k] = v
		drop[k] = true
	}
	var out []string
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		if (k == "NO_PROXY" || k == "no_proxy") && v != "" {
			if _, ok := setKeys["NO_PROXY"]; ok {
				setKeys["NO_PROXY"] += "," + v
				continue
			}
		}
		if !drop[k] {
			out = append(out, kv)
		}
	}
	for _, kv := range set {
		k, _, _ := strings.Cut(kv, "=")
		out = append(out, k+"="+setKeys[k])
	}
	return out
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=,@%+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// commandLine renders the launch as one shell line: environment, binary and
// arguments. The task argument is shown as <task> when task is not "".
func commandLine(bin string, l launch, task string) string {
	var parts []string
	for _, k := range l.Unset {
		parts = append(parts, "-u", k)
	}
	parts = append(parts, l.Env...)
	quoted := make([]string, 0, len(parts)+len(l.Args)+2)
	if len(parts) > 0 {
		quoted = append(quoted, "env")
		for _, p := range parts {
			quoted = append(quoted, shellQuote(p))
		}
	}
	quoted = append(quoted, shellQuote(bin))
	for _, a := range l.Args {
		if task != "" && a == task {
			quoted = append(quoted, "<task>")
			continue
		}
		quoted = append(quoted, shellQuote(a))
	}
	return strings.Join(quoted, " ")
}
