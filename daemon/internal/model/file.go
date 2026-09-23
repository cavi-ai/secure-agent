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
}

// FileAccess is one agent-session file event on a file.
type FileAccess struct {
	Kind      string `json:"kind"` // file-open | file-write | file-delete
	TS        string `json:"ts"`
	PID       int32  `json:"pid"`
	ExePath   string `json:"exe_path,omitempty"`
	SessionID string `json:"session_id"`
}
