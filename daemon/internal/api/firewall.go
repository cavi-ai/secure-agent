package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// systemDirs are locations a user secret file never legitimately lives; a source
// under any of them would only turn the root daemon into a system-file reader.
var systemDirs = []string{
	"/etc", "/private/etc", "/System", "/Library",
	"/usr", "/bin", "/sbin", "/var/db", "/private/var/db",
}

// validateSourcePath confines a registered ingest source to a plausible user
// secret file: an absolute regular file, its real path (symlinks resolved) not
// inside a system store. The daemon reads the source as root, so this is the
// gate that keeps source-add from becoming an arbitrary-file-read.
func validateSourcePath(raw string) error {
	p := config.ExpandPath(strings.TrimSpace(raw))
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path must be absolute or ~-relative")
	}
	resolved := filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		resolved = filepath.Clean(r)
	}
	for _, deny := range systemDirs {
		if resolved == deny || strings.HasPrefix(resolved, deny+"/") {
			return fmt.Errorf("refusing to ingest a system path: %s", resolved)
		}
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("not readable: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("must be a regular file")
	}
	return nil
}

type fwModeRequest struct {
	Rule string `json:"rule"`
	Type string `json:"type"` // when rule is empty: promote every pattern of this secret type
	Mode string `json:"mode"` // "monitor" | "block"
}

func (a *API) applyRuleMode(rule, mode string) error {
	prevMode := a.fwEngine.RuleMode(rule).String()
	if prevMode == mode {
		return nil
	}
	a.fwEngine.SetRuleMode(rule, firewall.ParseMode(mode))
	if a.fwModes != nil {
		if err := a.fwModes.Set(rule, mode); err != nil {
			return err
		}
	}
	a.store.PutAudit(store.AuditEntry{Action: "rule-mode", Rule: rule, FromMode: prevMode, ToMode: mode})
	return nil
}

// handleFirewallMode promotes or demotes a firewall rule at runtime and persists
// the override so it survives a restart. With {"type":"vendor-key","mode":"block"}
// and no rule, every configured pattern of that secret type is promoted.
func (a *API) handleFirewallMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwEngine == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req fwModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Rule == "" && req.Type == "") || (req.Mode != "monitor" && req.Mode != "block") {
		http.Error(w, `Invalid payload: {"rule":"<id>","mode":"monitor|block"} or {"type":"vendor-key","mode":"block"}`, http.StatusBadRequest)
		return
	}

	ids := []string{req.Rule}
	if req.Rule == "" {
		ids = a.fwEngine.RuleIDsOfType(req.Type)
	}
	promoted := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		prev := a.fwEngine.RuleMode(id).String()
		if err := a.applyRuleMode(id, req.Mode); err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		if prev != req.Mode {
			promoted = append(promoted, id)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"rule":     req.Rule,
		"type":     req.Type,
		"mode":     req.Mode,
		"promoted": promoted,
	})
}

// handleFingerprintReload re-reads the persisted fingerprints and applies them
// to the running engine, so `secure-agent fingerprint` takes effect without a
// daemon restart.
func (a *API) handleFingerprintReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwReload == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	if err := a.fwReload(); err != nil {
		http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "fingerprint-reload"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

// handleFingerprintIngest scans the configured secret sources, registers their
// fingerprints (HMAC only), applies them live, and returns the labels registered.
func (a *API) handleFingerprintIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.fwIngest == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}
	labels, err := a.fwIngest()
	if err != nil {
		http.Error(w, fmt.Sprintf("ingest failed: %v", err), http.StatusInternalServerError)
		return
	}
	// Record the count only — never the labels, which carry source paths.
	a.store.PutAudit(store.AuditEntry{Action: "fingerprint-ingest", Detail: fmt.Sprintf("%d secret(s) registered", len(labels))})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "registered": labels})
}

type sourceRow struct {
	Source string `json:"source"`
	Origin string `json:"origin"` // "config" (read-only) | "user"
}

type sourceRequest struct {
	Source string `json:"source"`
	Op     string `json:"op"` // "add" | "remove"
}

// handleFirewallSources lists (GET) and edits (POST) the ingest sources — the
// files whose KEY=VALUE secrets get fingerprinted. Config-defined sources are
// read-only; only user-added sources can be removed. Every edit re-ingests so
// the fingerprint set converges on the effective source list, and is audited
// with the path (the path is the subject of the change, never a secret value).
func (a *API) handleFirewallSources(w http.ResponseWriter, r *http.Request) {
	if a.fwSources == nil {
		http.Error(w, "firewall not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows := make([]sourceRow, 0, len(a.fwBaseSources))
		for _, s := range a.fwBaseSources {
			rows = append(rows, sourceRow{Source: s, Origin: "config"})
		}
		for _, s := range a.fwSources.Load() {
			rows = append(rows, sourceRow{Source: s, Origin: "user"})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)

	case http.MethodPost:
		limitBody(w, r)
		var req sourceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		req.Source = strings.TrimSpace(req.Source)
		if req.Source == "" || (req.Op != "add" && req.Op != "remove") {
			http.Error(w, `Invalid payload: {"source":"<path>","op":"add|remove"}`, http.StatusBadRequest)
			return
		}

		switch req.Op {
		case "add":
			// The daemon runs as root and reads whatever source is registered, so
			// an unvalidated path is an arbitrary-file-read primitive. Confine adds
			// to plausible user secret files: a regular file, not a system store.
			if err := validateSourcePath(req.Source); err != nil {
				http.Error(w, fmt.Sprintf("invalid source: %v", err), http.StatusBadRequest)
				return
			}
			if _, err := a.fwSources.Add(req.Source); err != nil {
				http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
				return
			}
			a.store.PutAudit(store.AuditEntry{Action: "source-add", Detail: req.Source})
		case "remove":
			removed, err := a.fwSources.Remove(req.Source)
			if err != nil {
				http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
				return
			}
			if !removed {
				http.Error(w, "not a user-added source (config sources are read-only)", http.StatusBadRequest)
				return
			}
			a.store.PutAudit(store.AuditEntry{Action: "source-remove", Detail: req.Source})
		}

		// Re-ingest so the fingerprint set tracks the effective source list. A
		// full re-ingest overwrites the persisted set, so a removed source's
		// fingerprints are purged.
		registered := 0
		if a.fwIngest != nil {
			labels, err := a.fwIngest()
			if err != nil {
				http.Error(w, fmt.Sprintf("re-ingest failed: %v", err), http.StatusInternalServerError)
				return
			}
			registered = len(labels)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "source": req.Source, "op": req.Op, "registered": registered})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
