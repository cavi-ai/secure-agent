// Package taint applies the guard hook's untrusted-egress rule to proxied
// connections. The hook keeps one record per session that read untrusted
// content; a routed client in such a session is refused when the rule
// resolves to deny for the session's workspace.
package taint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Rule is the hook's guard rule for egress after untrusted input.
const Rule = "untrusted-egress"

// InjectedRule applies on top of Rule once a session read text the injection
// detector matched.
const InjectedRule = "untrusted-egress-injected"

// Category is the hook's send kind for a proxied connection.
const Category = "network-send"

// shippedMode is each rule's mode when no override names it.
const shippedMode = "monitor"

var strictness = map[string]int{"monitor": 0, "session": 1, "prompt": 2, "deny": 3}

// rank orders modes as the hook does; an unknown mode ranks as deny.
func rank(mode string) int {
	if r, ok := strictness[mode]; ok {
		return r
	}
	return strictness["deny"]
}

func stricter(a, b string) string {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Verdict is the gate's answer for one proxied connection.
type Verdict struct {
	Blocked   bool
	Detail    string
	PID       int32
	SessionID string
}

// Gate refuses proxied connections from sessions the hook recorded as having
// read untrusted content, when the rule's mode for the session is deny.
type Gate struct {
	// Dir holds the hook's taint records, one per session.
	Dir string
	// ModesPath, CwdOverridesPath and CategoriesPath are the mode files the
	// hook reads.
	ModesPath        string
	CwdOverridesPath string
	CategoriesPath   string
	// Exempt hosts are never refused.
	Exempt map[string]bool
	// ClientPID names the process holding the client end of a connection.
	ClientPID func(ctx context.Context, remoteAddr string) (int32, error)
	// Sessions names the live sessions on a process's root: one per thread
	// for an app server, which cannot tell the threads' connections apart.
	Sessions func(pid int32) []Session
}

// Session is one live session and its workspace.
type Session struct {
	ID, Workspace string
}

// Check decides one connection to target (host or host:port). It looks up
// the client process only when a taint record exists and some workspace
// resolves the rule to deny. A client it cannot attribute is not refused;
// a root hosting several sessions is refused when any of them would be.
func (g *Gate) Check(ctx context.Context, remoteAddr, target string) Verdict {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || g.Exempt[host] || !g.anyRecord() {
		return Verdict{}
	}
	p := policy{
		overrides:  loadModes(g.ModesPath),
		entries:    loadCwdOverrides(g.CwdOverridesPath),
		categories: loadCategories(g.CategoriesPath),
	}
	if !p.mayDeny() {
		return Verdict{}
	}
	pid, err := g.ClientPID(ctx, remoteAddr)
	if err != nil {
		return Verdict{}
	}
	for _, sess := range g.Sessions(pid) {
		if sess.ID == "" {
			continue
		}
		rec, tainted := g.record(sess.ID)
		if !tainted || !denies(p.mode(sess.Workspace, rec.injected)) {
			continue
		}
		return Verdict{
			Blocked:   true,
			PID:       pid,
			SessionID: sess.ID,
			Detail:    fmt.Sprintf("proxy-untrusted-egress: %s after untrusted content (%s)", host, rec.source),
		}
	}
	return Verdict{}
}

func (g *Gate) anyRecord() bool {
	entries, err := os.ReadDir(g.Dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			return true
		}
	}
	return false
}

type taintRecord struct {
	source   string
	injected bool
}

// record reports whether the session has a taint record, its first source
// and whether it holds an injection match. An unreadable record counts as
// injected taint, as the hook fails closed on it.
func (g *Gate) record(id string) (taintRecord, bool) {
	// The hook clips session ids to 64 characters before hashing them.
	if r := []rune(id); len(r) > 64 {
		id = string(r[:64])
	}
	sum := sha256.Sum256([]byte(id))
	data, err := os.ReadFile(filepath.Join(g.Dir, hex.EncodeToString(sum[:])[:32]+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return taintRecord{}, false
	}
	var rec struct {
		Source    string          `json:"source"`
		Injection json.RawMessage `json:"injection"`
	}
	if err != nil || json.Unmarshal(data, &rec) != nil {
		return taintRecord{source: "unreadable", injected: true}, true
	}
	out := taintRecord{source: rec.Source, injected: len(rec.Injection) > 0 && string(rec.Injection) != "null"}
	if out.source == "" {
		out.source = "unknown"
	}
	if len(out.source) > 200 {
		out.source = out.source[:200]
	}
	return out, true
}

// denies mirrors the hook: the proxy cannot prompt, so only deny or a mode
// the hook does not know refuses.
func denies(mode string) bool {
	return rank(mode) >= strictness["deny"]
}

// resolveMode is the hook's chain: per-cwd overlay > global override file >
// shipped default. A "*" entry marks a corrupt file and wins.
func resolveMode(rule string, cwd, overrides map[string]string) string {
	if m, ok := cwd["*"]; ok {
		return m
	}
	if m, ok := cwd[rule]; ok {
		return m
	}
	if m, ok := overrides["*"]; ok {
		return m
	}
	if m, ok := overrides[rule]; ok {
		return m
	}
	return shippedMode
}

type policy struct {
	overrides  map[string]string
	entries    []cwdOverride
	categories map[string]string
}

// mode is the hook's untrusted-egress mode for a network send from
// workspace: the rule, replaced by the send kind's own mode, then raised to
// the injected rule when the session matched the injection detector.
func (p policy) mode(workspace string, injected bool) string {
	return p.modeFor(cwdModes(p.entries, workspace), injected)
}

func (p policy) modeFor(cwd map[string]string, injected bool) string {
	m := resolveMode(Rule, cwd, p.overrides)
	if c, ok := p.categories["*"]; ok {
		m = c
	} else if c, ok := p.categories[Category]; ok {
		m = c
	}
	if injected {
		m = stricter(m, resolveMode(InjectedRule, cwd, p.overrides))
	}
	return m
}

// mayDeny reports whether any workspace can resolve to deny, so the client
// lookup is skipped while every mode is monitor, session or prompt.
func (p policy) mayDeny() bool {
	if denies(p.modeFor(nil, true)) {
		return true
	}
	for _, e := range p.entries {
		if denies(p.modeFor(e.rules, true)) {
			return true
		}
	}
	return false
}

type cwdOverride struct {
	prefix string
	rules  map[string]string
}

// cwdModes returns the rules of the first overlay whose prefix contains
// workspace, or none.
func cwdModes(entries []cwdOverride, workspace string) map[string]string {
	if workspace == "" {
		return nil
	}
	cwd := filepath.Clean(workspace)
	for _, e := range entries {
		if e.prefix != "" && (cwd == e.prefix || strings.HasPrefix(cwd, strings.TrimSuffix(e.prefix, string(os.PathSeparator))+string(os.PathSeparator))) {
			return e.rules
		}
	}
	return nil
}

// loadModes reads the global override file: missing is none, unreadable or
// malformed denies.
func loadModes(path string) map[string]string {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var raw map[string]any
	if err != nil || json.Unmarshal(data, &raw) != nil || raw == nil {
		return map[string]string{"*": "deny"}
	}
	return modeMap(raw)
}

// loadCwdOverrides reads the per-project overlays: missing is none,
// unreadable or malformed denies everywhere.
func loadCwdOverrides(path string) []cwdOverride {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var raw []map[string]any
	if err != nil || json.Unmarshal(data, &raw) != nil {
		return []cwdOverride{{prefix: string(os.PathSeparator), rules: map[string]string{"*": "deny"}}}
	}
	out := make([]cwdOverride, 0, len(raw))
	for _, e := range raw {
		prefix, _ := e["cwd_prefix"].(string)
		rules, _ := e["rules"].(map[string]any)
		out = append(out, cwdOverride{prefix: expandPath(prefix), rules: modeMap(rules)})
	}
	return out
}

// modeMap keeps rule modes as the hook sees them: a value that is not a
// string is no mode the hook knows, so it denies.
func modeMap(raw map[string]any) map[string]string {
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

// loadCategories reads the per-kind modes for the rule: missing is none,
// unreadable, malformed or an unknown mode denies.
func loadCategories(path string) map[string]string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	corrupt := map[string]string{"*": "deny"}
	var raw map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &raw) != nil || raw == nil {
		return corrupt
	}
	body, ok := raw[Rule]
	if !ok {
		return nil
	}
	var rule map[string]any
	if json.Unmarshal(body, &rule) != nil || rule == nil {
		return corrupt
	}
	out := make(map[string]string, len(rule))
	for k, v := range rule {
		m, ok := v.(string)
		if _, known := strictness[m]; !ok || !known {
			return corrupt
		}
		out[k] = m
	}
	return out
}

func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = os.ExpandEnv(p)
	if strings.HasPrefix(p, "~") {
		home, _ := os.UserHomeDir()
		p = home + p[1:]
	}
	return filepath.Clean(p)
}
