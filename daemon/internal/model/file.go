package model

// FileFinding is one flag or incident whose evidence names a file.
type FileFinding struct {
	Kind         string `json:"kind"` // flag | incident
	ID           string `json:"id"`
	Rule         string `json:"rule"`
	Severity     int    `json:"severity,omitempty"` // flags
	Risk         string `json:"risk,omitempty"`     // incidents
	TS           string `json:"ts"`
	Agent        string `json:"agent,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	Acknowledged bool   `json:"acknowledged,omitempty"` // flags
	Status       string `json:"status,omitempty"`       // incidents
	// Flags: the evidence item naming the file — its kind, the rule it
	// matched and, for transcript hits, its line's byte offset (0 = unknown).
	EvidenceKind string `json:"evidence_kind,omitempty"`
	EvidenceRule string `json:"evidence_rule,omitempty"`
	Offset       int64  `json:"offset,omitempty"`
}

// FileHit is one secret found in a transcript: the flag that recorded it,
// the rule and the byte offset of its line (0 = unknown).
type FileHit struct {
	FlagID string `json:"flag_id"`
	Rule   string `json:"rule"`
	Offset int64  `json:"offset,omitempty"`
	TS     string `json:"ts"`
}

// FileDetail is what the daemon knows about one evidence file. Excerpt is
// the masked text around each hit; ExcerptWithheld says why it is empty
// when hits exist.
type FileDetail struct {
	Path            string          `json:"path"`
	Display         string          `json:"display"`
	Exists          bool            `json:"exists"`
	Size            int64           `json:"size"`
	ModTime         string          `json:"mod_time,omitempty"`
	OwnedByUser     bool            `json:"owned_by_user"`
	Subject         *ExplainSubject `json:"subject,omitempty"`
	Session         *Session        `json:"session,omitempty"`
	Findings        []FileFinding   `json:"findings"`
	Accesses        []FileAccess    `json:"accesses"`
	Hits            []FileHit       `json:"hits"`
	Excerpt         string          `json:"excerpt,omitempty"`
	ExcerptWithheld string          `json:"excerpt_withheld,omitempty"`
}

// FileAccess is one agent-session file event on a file.
type FileAccess struct {
	Kind      string `json:"kind"` // file-open | file-write | file-delete
	TS        string `json:"ts"`
	PID       int32  `json:"pid"`
	ExePath   string `json:"exe_path,omitempty"`
	SessionID string `json:"session_id"`
}
