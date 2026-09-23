package model

import (
	"encoding/json"
	"time"
)

// EvidenceItem: structured flag evidence. Text carries legacy pre-structure
// rows; Kind "text" marks those.
type EvidenceItem struct {
	Kind  string `json:"kind"` // read | connect | keychain | exec | tcc | violation | text
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	Rule  string `json:"rule,omitempty"` // read items: the classifier rule or glob that matched
	TS    string `json:"ts,omitempty"`
	Text  string `json:"text,omitempty"`
}

// UnmarshalJSON accepts the legacy bare-string form too.
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

// String renders the legacy display string.
func (e EvidenceItem) String() string {
	if e.Text != "" {
		return e.Text
	}
	if e.Sub != "" {
		return e.Label + " (" + e.Sub + ")"
	}
	return e.Label
}

// EvidenceStrings renders the list as display strings.
func (f Flag) EvidenceStrings() []string {
	out := make([]string, 0, len(f.Evidence))
	for _, ev := range f.Evidence {
		out = append(out, ev.String())
	}
	return out
}

// EvidenceFromStrings builds text-kind items (tests, legacy call sites).
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
	// Explain is the plain-language reading of the flag, stamped at serve
	// time (GET /flags/{id}/explain, and the first 25 unacknowledged flags
	// of /flags and /snapshot). Not persisted.
	Explain *FlagExplain `json:"explain,omitempty"`
}
