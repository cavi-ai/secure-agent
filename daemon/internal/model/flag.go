package model

import (
	"encoding/json"
	"time"
)

// EvidenceItem is one structured piece of flag evidence. Producers
// (correlate) set Kind/Label/Sub/TS at detection time so no client ever
// parses a display string. Text carries legacy rows written before evidence
// was structured; Kind "text" marks those.
type EvidenceItem struct {
	Kind  string `json:"kind"` // read | connect | keychain | exec | tcc | violation | text
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	TS    string `json:"ts,omitempty"`
	Text  string `json:"text,omitempty"`
}

// UnmarshalJSON accepts both the legacy form (a bare string) and the
// structured form, so rows written by older daemons still decode.
func (e *EvidenceItem) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		e.Kind = "text"
		e.Label = s
		e.Text = s
		return nil
	}
	type alias EvidenceItem
	return json.Unmarshal(data, (*alias)(e))
}

// String renders the item as the legacy display string — the form intel and
// advisor prompts consume.
func (e EvidenceItem) String() string {
	if e.Text != "" {
		return e.Text
	}
	if e.Sub != "" {
		return e.Label + " (" + e.Sub + ")"
	}
	return e.Label
}

// EvidenceStrings renders the evidence list as legacy display strings for
// text consumers (intel analyzer, advisor prompts, incident markdown).
func (f Flag) EvidenceStrings() []string {
	out := make([]string, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		out = append(out, ev.String())
	}
	return out
}

// EvidenceFromStrings builds text-kind evidence items — for tests and
// legacy-string call sites.
func EvidenceFromStrings(strs ...string) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(strs))
	for _, s := range strs {
		out = append(out, EvidenceItem{Kind: "text", Label: s, Text: s})
	}
	return out
}

type Flag struct {
	ID       string    `json:"id"`
	Rule     string    `json:"rule"`
	Severity int       `json:"severity"`
	TS       time.Time `json:"ts"`
	PID      int32     `json:"pid"`
	Agent    string    `json:"agent"`
	// SessionID groups the flag with its harness session, so fleet consumers
	// can follow one agent run end-to-end even after PIDs are recycled.
	SessionID string `json:"session_id,omitempty"`
	// Workspace is the session's working directory, stamped at ingest. It is
	// the key for per-workspace notification scopes — "page me for leaks in
	// the prod repo, stay quiet in my scratch clones".
	Workspace string `json:"workspace,omitempty"`
	// Evidence is structured: producers set Kind/Label/Sub at detection time.
	// Rows written by older daemons decode as {kind:"text"} items.
	Evidence []EvidenceItem `json:"evidence"`
	// Title is the operator-facing rule name, stamped at serve time from the
	// daemon's single rule-title table. Not persisted; empty in stored rows.
	Title string `json:"title,omitempty"`
	// Advisor carries the local advisor's triage verdict when one exists.
	// Advisory only — never an enforcement input.
	Advisor *AdvisorVerdict `json:"advisor,omitempty"`
	// Acknowledged: the operator acted on this flag (applied a disposition).
	// Acknowledged flags stop counting as critical and render dimmed —
	// "acted upon" instead of an endless red row.
	Acknowledged bool `json:"acknowledged,omitempty"`
}
