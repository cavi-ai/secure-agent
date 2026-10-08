package api

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// flagExpectedPattern is the expected-pattern entry a read-then-connect flag
// stands for; false when its evidence does not record who read the file.
func flagExpectedPattern(f model.Flag) (correlate.ExpectedPattern, bool) {
	read, conn := evidenceOfKind(f, "read"), evidenceOfKind(f, "connect")
	if f.Rule != readConnectRule || f.Agent == "" || read == nil || conn == nil {
		return correlate.ExpectedPattern{}, false
	}
	toolRead := read.Sub == "agent tool read"
	host, _ := splitHostPort(conn.Label)
	if host == "" || (read.Exe == "" && !toolRead) {
		return correlate.ExpectedPattern{}, false
	}
	p := correlate.ExpectedPattern{
		Agent:  f.Agent,
		Reader: correlate.ReaderLabel(read.Exe, toolRead),
		Path:   read.Label,
		Dest:   correlate.DestLabel(host),
	}
	p.Key = correlate.ReadConnectKey(p.Agent, p.Reader, p.Path, p.Dest)
	return p, true
}

// expectAction offers marking f's pattern expected, unless it already is.
func (a *API) expectAction(f model.Flag) (model.ExplainAction, bool) {
	p, ok := a.nextExpectedPattern(f)
	if !ok || a.expected == nil || a.expected.Has(p.Key) {
		return model.ExplainAction{}, false
	}
	file := displayPath(p.Path, strings.TrimRight(explainHome(), "/"))
	return model.ExplainAction{
		ID: "expect", Label: "Expected: " + p.Reader + " → " + p.Dest,
		Consequence: "Later reads of " + file + " by " + p.Reader + " followed by a connection to " + p.Dest +
			" are counted, not flagged; open flags of this pattern are marked reviewed. A new reader, file or destination still flags. Forget it under Policy.",
		Method: http.MethodPost, Path: "/expected",
		Body: map[string]any{"flag_id": f.ID, "path": p.Path, "host": p.Dest},
	}, true
}

// handleExpected lists (GET), adds from a flag (POST {"flag_id"}) and
// forgets (DELETE ?key=) the read-then-connect patterns the operator marked
// expected. POST {"flag_ids"} adds every exact pair those flags cite.
func (a *API) handleExpected(w http.ResponseWriter, r *http.Request) {
	if a.expected == nil {
		http.Error(w, "expected patterns not enabled", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.expected.List())
	case http.MethodPost:
		limitBody(w, r)
		var req struct {
			FlagID  string   `json:"flag_id"`
			FlagIDs []string `json:"flag_ids"`
			Scope   string   `json:"scope"`
			Path    string   `json:"path"`
			Host    string   `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.FlagID == "") == (len(req.FlagIDs) == 0) {
			http.Error(w, `Invalid payload: {"flag_id":"<id>"} or {"flag_ids":["<id>",...]}`, http.StatusBadRequest)
			return
		}
		if len(req.FlagIDs) > 0 {
			a.expectFlags(w, req.FlagIDs)
			return
		}
		f, ok := a.store.GetFlag(req.FlagID)
		if !ok {
			http.Error(w, "unknown flag", http.StatusNotFound)
			return
		}
		p, ok := flagExpectedPattern(f)
		if req.Path != "" || req.Host != "" {
			ok = false
			for _, candidate := range expectedPairs(f) {
				if candidate.Path == req.Path && candidate.Dest == correlate.DestLabel(req.Host) {
					p = candidate
					ok = true
					break
				}
			}
		}
		if !ok {
			http.Error(w, "flag is not a read-then-connect flag with a recorded reader", http.StatusUnprocessableEntity)
			return
		}
		if req.Scope != "" && req.Scope != "file" {
			http.Error(w, "unknown exception scope", http.StatusBadRequest)
			return
		}
		if req.Scope == "file" {
			base := filepath.Base(p.Path)
			if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || !(base == ".env" || strings.HasPrefix(base, ".env.")) {
				http.Error(w, "file exceptions require an exact .env path", http.StatusUnprocessableEntity)
				return
			}
			p.Scope = "file"
			p.Reader = "*"
			p.Dest = "*"
		}
		p.CreatedAt = time.Now().UTC()
		stored, err := a.expected.Add(p)
		if err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		acked := a.acknowledgeExpected()
		a.recordLabel(model.OperatorLabel{Kind: "flag", Rule: readConnectRule, Agent: stored.Agent, Pattern: stored.Path, Label: "ok", Source: "expect"})
		a.store.PutAudit(store.AuditEntry{
			Action: "expect-add", Rule: readConnectRule,
			Detail: fmt.Sprintf("expected scope=%s %s reading %s near %s for %s (%d open flags acknowledged)", stored.Scope, stored.Reader, stored.Path, stored.Dest, stored.Agent, acked),
		})
		writeJSON(w, stored)
	case http.MethodDelete:
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "DELETE requires ?key=<pattern key>", http.StatusBadRequest)
			return
		}
		removed, err := a.expected.Remove(key)
		if err != nil {
			http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
			return
		}
		if !removed {
			http.Error(w, "unknown pattern", http.StatusNotFound)
			return
		}
		a.store.PutAudit(store.AuditEntry{Action: "expect-remove", Rule: readConnectRule, Detail: "forgot expected pattern " + key})
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// expectFlags marks every exact read-then-connect pair the flags cite
// expected, with one save, then reviews the flags the exceptions now fully
// cover. A flag without a recorded reader adds nothing and stays open.
func (a *API) expectFlags(w http.ResponseWriter, ids []string) {
	if len(ids) > model.PatternFlagIDCap {
		http.Error(w, fmt.Sprintf("at most %d flag ids", model.PatternFlagIDCap), http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	var pairs []correlate.ExpectedPattern
	for _, id := range ids {
		if f, ok := a.store.GetFlag(id); ok {
			for _, p := range expectedPairs(f) {
				p.CreatedAt = now
				pairs = append(pairs, p)
			}
		}
	}
	if len(pairs) == 0 {
		http.Error(w, "no read-then-connect flag with a recorded reader", http.StatusUnprocessableEntity)
		return
	}
	added, err := a.expected.AddAll(pairs)
	if err != nil {
		http.Error(w, fmt.Sprintf("persist failed: %v", err), http.StatusInternalServerError)
		return
	}
	acked := a.acknowledgeExpected()
	for _, p := range added {
		a.recordLabel(model.OperatorLabel{Kind: "flag", Rule: readConnectRule, Agent: p.Agent, Pattern: p.Path, Label: "ok", Source: "expect"})
	}
	a.store.PutAudit(store.AuditEntry{
		Action: "expect-add", Rule: readConnectRule,
		Detail: fmt.Sprintf("expected %d exact reader, file and destination pairs from %d flags (%d open flags acknowledged)", len(added), len(ids), acked),
	})
	writeJSON(w, map[string]int{"added": len(added), "acknowledged": acked})
}

// acknowledgeExpected reviews only findings fully covered by current exceptions.
func (a *API) acknowledgeExpected() int {
	open := a.store.QueryFlags(store.FlagFilter{Rule: readConnectRule, Unacted: true, Limit: math.MaxInt32})
	var ids []string
	for _, f := range open {
		if a.flagFullyExpected(f) {
			ids = append(ids, f.ID)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	return a.store.AcknowledgeFlags(ids)
}

// A finding may cite several files and endpoints. Resolve it only when
// every pair is covered; a single selected pair cannot hide the rest.
func (a *API) flagFullyExpected(f model.Flag) bool {
	if a.expected == nil || f.Rule != readConnectRule {
		return false
	}
	reads, conns := 0, 0
	for _, r := range f.Evidence {
		if r.Kind != "read" {
			continue
		}
		reads++
		reader := correlate.ReaderLabel(r.Exe, r.Sub == "agent tool read")
		if r.Exe == "" && r.Sub != "agent tool read" {
			return false
		}
		for _, cm := range f.Evidence {
			if cm.Kind != "connect" {
				continue
			}
			conns++
			host, _ := splitHostPort(cm.Label)
			if host == "" || !a.expected.Has(correlate.ReadConnectKey(f.Agent, reader, r.Label, correlate.DestLabel(host))) {
				return false
			}
		}
	}
	return reads > 0 && conns > 0
}

func (a *API) nonSecretFileAction(f model.Flag) (model.ExplainAction, bool) {
	if a.expected == nil || f.Rule != readConnectRule {
		return model.ExplainAction{}, false
	}
	for _, read := range f.Evidence {
		base := filepath.Base(read.Label)
		if read.Kind != "read" || !filepath.IsAbs(read.Label) || !(base == ".env" || strings.HasPrefix(base, ".env.")) {
			continue
		}
		key := correlate.ReadConnectKey(f.Agent, "*", read.Label, "*")
		if a.expected.Has(key) {
			continue
		}
		conn := evidenceOfKind(f, "connect")
		if conn == nil {
			continue
		}
		host, _ := splitHostPort(conn.Label)
		return model.ExplainAction{ID: "expect-file", Label: "Mark this .env as a test / non-secret file",
			Consequence: "Exempt only " + read.Label + " for " + f.Agent + " from read/connect findings until revoked under Policy. This includes future contents and every destination. Use only for files that contain no real credentials. Other files and agents stay monitored; guard protection stays active.",
			Method:      http.MethodPost, Path: "/expected", Body: map[string]any{"flag_id": f.ID, "scope": "file", "path": read.Label, "host": host}}, true
	}
	return model.ExplainAction{}, false
}

func expectedPairs(f model.Flag) []correlate.ExpectedPattern {
	var out []correlate.ExpectedPattern
	if f.Rule != readConnectRule {
		return nil
	}
	for _, r := range f.Evidence {
		if r.Kind != "read" {
			continue
		}
		for _, cm := range f.Evidence {
			if cm.Kind != "connect" {
				continue
			}
			pair := f
			pair.Evidence = []model.EvidenceItem{r, cm}
			if p, ok := flagExpectedPattern(pair); ok {
				out = append(out, p)
			}
		}
	}
	return out
}
func (a *API) nextExpectedPattern(f model.Flag) (correlate.ExpectedPattern, bool) {
	for _, p := range expectedPairs(f) {
		if a.expected == nil || !a.expected.Has(p.Key) {
			return p, true
		}
	}
	return correlate.ExpectedPattern{}, false
}
