package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func decodePolicyEdit(w http.ResponseWriter, r *http.Request, req any) error {
	limitBody(w, r)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(req); err != nil {
		return fmt.Errorf("invalid policy edit")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("expected one policy edit")
	}
	return nil
}

func (a *API) handleFirewallPatterns(w http.ResponseWriter, r *http.Request) {
	if a.fwEngine == nil {
		http.Error(w, "firewall not enabled", 503)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, a.fwEngine.Patterns())
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Op      string               `json:"op"`
		ID      string               `json:"id"`
		Pattern config.PatternConfig `json:"pattern"`
	}
	if err := decodePolicyEdit(w, r, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.policyWriteMu.Lock()
	defer a.policyWriteMu.Unlock()
	patterns := a.fwEngine.Patterns()
	id := req.ID
	if req.Op == "add" {
		id = req.Pattern.ID
	}
	index := -1
	for i, p := range patterns {
		if p.ID == id {
			index = i
			break
		}
	}
	switch req.Op {
	case "add":
		if index >= 0 {
			http.Error(w, "rule ID already exists", 409)
			return
		}
		patterns = append(patterns, req.Pattern)
	case "edit":
		if index < 0 {
			http.Error(w, "rule not found", 404)
			return
		}
		if req.Pattern.ID != id {
			http.Error(w, "rule ID cannot change", 400)
			return
		}
		// Mode changes remain on the durable /firewall/mode endpoint.
		req.Pattern.Mode = patterns[index].Mode
		patterns[index] = req.Pattern
	case "remove":
		if index < 0 {
			http.Error(w, "rule not found", 404)
			return
		}
		patterns = append(patterns[:index], patterns[index+1:]...)
	default:
		http.Error(w, "operation must be add, edit, or remove", 400)
		return
	}
	if err := config.ValidateFirewallPatterns(patterns); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := a.fwEngine.ReplacePatterns(patterns, func() error { return config.WriteFirewallPatterns(a.configPath, patterns) }); err != nil {
		http.Error(w, "could not persist firewall patterns", 500)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "firewall-pattern-" + req.Op, Rule: id})
	a.PublishPostureIfChanged()
	writeJSON(w, a.fwEngine.Patterns())
}

func (a *API) handleGuardConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if a.socketPath == "" {
		http.Error(w, "guard policy path unavailable", 503)
		return
	}
	a.policyWriteMu.Lock()
	defer a.policyWriteMu.Unlock()
	path := filepath.Join(filepath.Dir(a.socketPath), "guard-rules.json")
	doc, err := config.LoadGuardPolicy(path)
	if err != nil {
		http.Error(w, "guard configuration is unreadable; repair it before editing", 500)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, doc)
		return
	}
	var req struct {
		Op   string               `json:"op"`
		ID   string               `json:"id"`
		Rule config.GuardPathRule `json:"rule"`
	}
	if err := decodePolicyEdit(w, r, &req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id := req.ID
	if req.Op == "add" {
		id = req.Rule.ID
	}
	index := -1
	for i, rule := range doc.Rules {
		if rule.ID == id {
			index = i
			break
		}
	}
	switch req.Op {
	case "add":
		if index >= 0 {
			http.Error(w, "rule ID already exists", 409)
			return
		}
		// Explicit additions precede shipped rules, so a narrower custom path
		// is not shadowed by a broad shipped glob such as **/.env.
		doc.Rules = append([]config.GuardPathRule{req.Rule}, doc.Rules...)
	case "edit":
		if index < 0 {
			http.Error(w, "rule not found", 404)
			return
		}
		if req.Rule.ID != id {
			http.Error(w, "rule ID cannot change", 400)
			return
		}
		doc.Rules[index] = req.Rule
	case "remove":
		if index < 0 {
			http.Error(w, "rule not found", 404)
			return
		}
		doc.Rules = append(doc.Rules[:index], doc.Rules[index+1:]...)
		filtered := make([][]string, 0, len(doc.DirScan))
		for _, pair := range doc.DirScan {
			if pair[1] != id {
				filtered = append(filtered, pair)
			}
		}
		doc.DirScan = filtered
	default:
		http.Error(w, "operation must be add, edit, or remove", 400)
		return
	}
	if req.Op == "edit" || req.Op == "add" {
		filtered := make([][]string, 0, len(doc.DirScan))
		for _, pair := range doc.DirScan {
			if pair[1] != id {
				filtered = append(filtered, pair)
			}
		}
		for _, p := range req.Rule.Paths {
			if strings.HasSuffix(p, "/**") {
				filtered = append(filtered, []string{strings.TrimSuffix(p, "/**"), id})
			}
		}
		doc.DirScan = filtered
	}
	if err := config.ValidateGuardPolicy(doc); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := config.WriteGuardPolicy(path, doc); err != nil {
		http.Error(w, "could not persist guard rules", 500)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "guard-policy-" + req.Op, Rule: id})
	writeJSON(w, doc)
}
