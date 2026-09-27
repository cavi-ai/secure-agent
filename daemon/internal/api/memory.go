package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
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

func memoryToolLabel(tool string) string {
	switch tool {
	case "Bash":
		return "Shell command"
	case "Read":
		return "File read"
	case "Write":
		return "File write"
	case "Edit":
		return "File edit"
	case "Glob":
		return "File search"
	case "Grep":
		return "Text search"
	case "WebSearch":
		return "Web search"
	case "WebFetch":
		return "Web fetch"
	default:
		return ""
	}
}

func memoryModelLabel(model string) string {
	switch model {
	case "claude-sonnet-4-5":
		return "Claude Sonnet 4.5"
	case "claude-sonnet-5":
		return "Claude Sonnet 5"
	case "claude-opus-4-6":
		return "Claude Opus 4.6"
	case "claude-opus-5":
		return "Claude Opus 5"
	case "gpt-5":
		return "GPT-5"
	case "gpt-5.5":
		return "GPT-5.5"
	case "gpt-5.6-sol":
		return "GPT-5.6 Sol"
	default:
		return ""
	}
}

func memoryDiagnosisLabel(code string) string {
	switch code {
	case "heavy-memory":
		return "Heavy memory"
	case "heavy-cpu":
		return "Heavy CPU"
	case "rapid-growth":
		return "Rapid memory growth"
	case "idle-heavy":
		return "High idle memory"
	case "runaway-child":
		return "Runaway child process"
	case "orphan-drift":
		return "Orphaned processes"
	default:
		return ""
	}
}

func memoryGuardRuleLabel(rule string) string {
	switch rule {
	case "cloud-creds":
		return "Cloud credentials"
	case "ssh-keys":
		return "SSH keys"
	case "keychain":
		return "Keychain"
	case "env-files":
		return "Environment files"
	case "shell-rc":
		return "Shell configuration"
	case "harness-config":
		return "Agent configuration"
	default:
		return "Guard rule"
	}
}

func memoryGuardVerdictLabel(verdict string) string {
	switch verdict {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	case "ask":
		return "Ask"
	default:
		return ""
	}
}

func memoryGuardScopeLabel(scope string) string {
	switch scope {
	case "once":
		return "Once"
	case "always":
		return "Always"
	default:
		return ""
	}
}

func memoryRSSLabel(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	for _, unit := range []struct {
		bytes uint64
		name  string
	}{{1 << 60, "EiB"}, {1 << 50, "PiB"}, {1 << 40, "TiB"}, {1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if bytes >= unit.bytes {
			if bytes%unit.bytes == 0 {
				return fmt.Sprintf("%d %s", bytes/unit.bytes, unit.name)
			}
			fraction := (bytes % unit.bytes) / (unit.bytes / 10)
			if fraction > 9 {
				fraction = 9
			}
			return fmt.Sprintf("%d.%d %s", bytes/unit.bytes, fraction, unit.name)
		}
	}
	return ""
}

func presentMemoryFact(f store.MemoryFact) memoryRow {
	r := memoryRow{ID: f.ID, At: f.At, Kind: f.Kind}
	switch f.Kind {
	case "activity":
		r.Title = "Activity: " + f.EventKind.String()
		var details []string
		if label := memoryToolLabel(f.Tool); label != "" {
			details = append(details, "Tool: "+label)
		} else if label := memoryModelLabel(f.Model); label != "" {
			details = append(details, "Model: "+label)
		}
		if f.EventKind == event.KindModelCall && (f.TokensIn > 0 || f.TokensOut > 0) {
			if f.TokensIn >= 0 {
				details = append(details, fmt.Sprintf("%d input tokens", f.TokensIn))
			}
			if f.TokensOut >= 0 {
				details = append(details, fmt.Sprintf("%d output tokens", f.TokensOut))
			}
		}
		r.Detail = strings.Join(details, " · ")
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
		details := []string{"Rule: " + memoryGuardRuleLabel(f.RuleID)}
		if label := memoryGuardVerdictLabel(f.Verdict); label != "" {
			details = append(details, "Decision: "+label)
		}
		if label := memoryGuardScopeLabel(f.Scope); label != "" {
			details = append(details, "Scope: "+label)
		}
		r.Detail = strings.Join(details, " · ")
	case "resource":
		r.Title = "Resource episode"
		var details []string
		switch f.SeverityText {
		case "info", "warning", "critical":
			r.Severity = f.SeverityText
		}
		if len(f.DiagnosisCodes) > 0 {
			if label := memoryDiagnosisLabel(f.DiagnosisCodes[0]); label != "" {
				details = append(details, "Diagnosis: "+label)
			}
		}
		if f.RSSBytes > 0 {
			details = append(details, "Memory: "+memoryRSSLabel(f.RSSBytes))
		}
		r.Detail = strings.Join(details, " · ")
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
