package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryRow struct {
	ID       string    `json:"id"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Status   string    `json:"status,omitempty"`
}

type memoryResponse struct {
	Rows       []memoryRow `json:"rows"`
	HasEarlier bool        `json:"has_earlier"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type memoryCursorWire struct {
	Version int    `json:"v"`
	At      int64  `json:"at"`
	Rank    int    `json:"rank"`
	ID      string `json:"id"`
}

func encodeMemoryCursor(f store.MemoryFact) string {
	b, _ := json.Marshal(memoryCursorWire{Version: 1, At: f.At.UnixNano(), Rank: f.SourceRank, ID: f.SourceID})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeMemoryCursor(raw string) (*store.MemoryCursor, error) {
	if len(raw) == 0 || len(raw) > 512 {
		return nil, fmt.Errorf("invalid cursor")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	var c memoryCursorWire
	if err := json.Unmarshal(b, &c); err != nil || c.Version != 1 || c.At <= 0 || c.Rank < 1 || c.Rank > 5 || !safeMemoryID(c.ID) {
		return nil, fmt.Errorf("invalid cursor")
	}
	return &store.MemoryCursor{At: time.Unix(0, c.At).UTC(), SourceRank: c.Rank, SourceID: c.ID}, nil
}

func safeMemoryID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func memoryRuleTitle(rule string) string {
	if !safeMemoryID(rule) {
		return "Security finding"
	}
	switch rule {
	case "proxy-secret-leak", "sensitive-read-then-connect", "keychain-access", "keychain-security-cli", "tcc-tamper", "proxy-prompt-injection", "secret-in-transcript":
		return humanFlagTitle(rule)
	default:
		return "Security finding"
	}
}

func presentMemoryFact(f store.MemoryFact) memoryRow {
	r := memoryRow{ID: f.ID, At: f.At, Kind: f.Kind}
	switch f.Kind {
	case "activity":
		r.Title = "Activity: " + f.EventKind.String()
		if safeMemoryID(f.Tool) {
			r.Detail = "Tool: " + f.Tool
		} else if safeMemoryID(f.Model) {
			r.Detail = "Model: " + f.Model
		}
	case "guard-audit":
		r.Title = "Secret guard activity"
		if f.Verdict == "allow" || f.Verdict == "deny" || f.Verdict == "ask" {
			r.Detail = "Decision: " + f.Verdict
		}
	case "flag":
		r.Title = memoryRuleTitle(f.RuleID)
		switch f.Severity {
		case 1:
			r.Severity = "low"
		case 2:
			r.Severity = "medium"
		case 3:
			r.Severity = "high"
		case 4:
			r.Severity = "critical"
		}
	case "incident":
		r.Title = "Incident: " + memoryRuleTitle(f.RuleID)
		if f.Count > 1 {
			r.Detail = fmt.Sprintf("%d related findings", f.Count)
		}
		switch f.Risk {
		case "low", "medium", "high", "critical":
			r.Severity = f.Risk
		}
		switch f.Status {
		case "open", "resolved", "dismissed":
			r.Status = f.Status
		}
	case "guard":
		r.Title = "Secret guard decision"
		if f.Verdict == "allow" || f.Verdict == "deny" || f.Verdict == "ask" {
			r.Detail = "Decision: " + f.Verdict
		}
	case "resource":
		r.Title = "Resource episode"
		switch f.SeverityText {
		case "info", "warning", "critical":
			r.Severity = f.SeverityText
		}
		if len(f.DiagnosisCodes) > 0 && safeMemoryID(f.DiagnosisCodes[0]) {
			r.Detail = "Diagnosis: " + f.DiagnosisCodes[0]
		}
	default:
		r.Title = "Session activity"
	}
	return r
}

func (a *API) serveSessionMemory(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := a.store.GetSession(id); !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	limit := 200
	if values, ok := q["limit"]; ok {
		if len(values) != 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		n, err := strconv.Atoi(values[0])
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		if n > 500 {
			n = 500
		}
		limit = n
	}
	var before *store.MemoryCursor
	if values, ok := q["before"]; ok {
		if len(values) != 1 {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		var err error
		before, err = decodeMemoryCursor(values[0])
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
	}
	facts, earlier, err := a.store.QuerySessionMemory(id, before, limit)
	if err != nil {
		http.Error(w, "memory unavailable", http.StatusInternalServerError)
		return
	}
	response := memoryResponse{Rows: make([]memoryRow, 0, len(facts)), HasEarlier: earlier}
	for _, f := range facts {
		response.Rows = append(response.Rows, presentMemoryFact(f))
	}
	if earlier && len(facts) > 0 {
		response.NextCursor = encodeMemoryCursor(facts[0])
	}
	writeJSON(w, response)
}
