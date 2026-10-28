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

// shippedMode is the rule's mode when no override names it.
const shippedMode = "monitor"

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
	// ModesPath and CwdOverridesPath are the mode files the hook reads.
	ModesPath        string
	CwdOverridesPath string
	// Exempt hosts are never refused.
	Exempt map[string]bool
	// ClientPID names the process holding the client end of a connection.
	ClientPID func(ctx context.Context, remoteAddr string) (int32, error)
	// Session names the live session a process belongs to, and its workspace.
	Session func(pid int32) (id, workspace string, ok bool)
}

// Check decides one connection to target (host or host:port). It looks up
// the client process only when a taint record exists and some workspace
// resolves the rule to deny. A client it cannot attribute is not refused.
func (g *Gate) Check(ctx context.Context, remoteAddr, target string) Verdict {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || g.Exempt[host] || !g.anyRecord() {
		return Verdict{}
	}
	overrides := loadModes(g.ModesPath)
	entries := loadCwdOverrides(g.CwdOverridesPath)
	if !mayDeny(overrides, entries) {
		return Verdict{}
	}
	pid, err := g.ClientPID(ctx, remoteAddr)
	if err != nil {
		return Verdict{}
	}
	id, workspace, ok := g.Session(pid)
	if !ok || id == "" {
		return Verdict{}
	}
	source, tainted := g.record(id)
	if !tainted || !denies(resolveMode(cwdModes(entries, workspace), overrides)) {
		return Verdict{}
	}
	return Verdict{
		Blocked:   true,
		PID:       pid,
		SessionID: id,
		Detail:    fmt.Sprintf("proxy-untrusted-egress: %s after untrusted content (%s)", host, source),
	}
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

// record reports whether the session has a taint record and its first
// source. An unreadable record counts as taint, as in the hook.
func (g *Gate) record(id string) (source string, ok bool) {
	// The hook clips session ids to 64 characters before hashing them.
	if len(id) > 64 {
		id = id[:64]
	}
	sum := sha256.Sum256([]byte(id))
	data, err := os.ReadFile(filepath.Join(g.Dir, hex.EncodeToString(sum[:])[:32]+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	var rec struct {
		Source string `json:"source"`
	}
	if err != nil || json.Unmarshal(data, &rec) != nil {
		return "unreadable", true
	}
	if rec.Source == "" {
		return "unknown", true
	}
	if len(rec.Source) > 200 {
		rec.Source = rec.Source[:200]
	}
	return rec.Source, true
}

// denies mirrors the hook: every mode but monitor and prompt refuses.
func denies(mode string) bool {
	return mode != "monitor" && mode != "prompt"
}

// resolveMode is the hook's chain: per-cwd overlay > global override file >
// shipped default. A "*" entry marks a corrupt file and wins.
func resolveMode(cwd, overrides map[string]string) string {
	if m, ok := cwd["*"]; ok {
		return m
	}
	if m, ok := cwd[Rule]; ok {
		return m
	}
	if m, ok := overrides["*"]; ok {
		return m
	}
	if m, ok := overrides[Rule]; ok {
		return m
	}
	return shippedMode
}

// mayDeny reports whether any workspace can resolve the rule to deny, so the
// client lookup is skipped while every mode is monitor or prompt.
func mayDeny(overrides map[string]string, entries []cwdOverride) bool {
	if denies(resolveMode(nil, overrides)) {
		return true
	}
	for _, e := range entries {
		if denies(resolveMode(e.rules, overrides)) {
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
