package model

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DecisionScope records permission coordinates, independently of risk and
// review state. ReaderExe is an observed path, not executable verification.
type DecisionScope struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	Agent         string    `json:"agent"`
	SessionID     string    `json:"session_id,omitempty"`
	Workspace     string    `json:"workspace,omitempty"`
	ReaderExe     string    `json:"reader_exe,omitempty"`
	RuleID        string    `json:"rule_id"`
	ResourcePath  string    `json:"resource_path"`
	Operation     string    `json:"operation"`
	Destination   string    `json:"destination,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
	IdentityBasis string    `json:"identity_basis"`
}

type ScopeChoice struct {
	Kind   string `json:"kind"`
	Expiry string `json:"expiry,omitempty"` // exact: 24h or 7d, chosen explicitly
}

func (c ScopeChoice) Validate() error {
	if (c.Kind == "once" || c.Kind == "session") && c.Expiry == "" {
		return nil
	}
	if c.Kind == "exact" && (c.Expiry == "24h" || c.Expiry == "7d") {
		return nil
	}
	return fmt.Errorf("choose once, session, or exact with expiry 24h or 7d")
}

func (c ScopeChoice) Apply(s *DecisionScope, now time.Time) {
	s.Kind = c.Kind
	s.CreatedAt = now
	if c.Expiry == "24h" {
		s.ExpiresAt = now.Add(24 * time.Hour)
	}
	if c.Expiry == "7d" {
		s.ExpiresAt = now.Add(7 * 24 * time.Hour)
	}
}

func ExactPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && len(p) <= 4096 && !strings.ContainsRune(p, 0)
}

// Endpoint retains the port; organization, suffix and host-only matches are
// deliberately insufficient for new permissions. Legacy policies stay separate.
func Endpoint(label string) string {
	i := strings.LastIndex(label, ":")
	if i < 1 {
		return ""
	}
	port, err := strconv.Atoi(label[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(strings.Trim(label[:i], "[]"), "."))
	if host == "" || strings.ContainsAny(host, " /\t\n\x00") {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s DecisionScope) Validate() error {
	if s.Kind == "once" {
		return nil
	}
	if s.Kind != "session" && s.Kind != "exact" {
		return fmt.Errorf("invalid scope kind")
	}
	if s.Agent == "" || s.SessionID == "" || !ExactPath(s.Workspace) || !ExactPath(s.ReaderExe) || !ExactPath(s.ResourcePath) || s.RuleID == "" || s.CreatedAt.IsZero() ||
		(s.IdentityBasis != "peer-process-tree" && s.IdentityBasis != "observed-session") {
		return fmt.Errorf("incomplete permission identity; choose once")
	}
	if s.Operation == "read-connect" {
		if s.Destination == "" || Endpoint(s.Destination) != s.Destination {
			return fmt.Errorf("exact endpoint required")
		}
	} else if !strings.HasPrefix(s.Operation, "guard:") || len(s.Operation) <= len("guard:") || s.Destination != "" {
		return fmt.Errorf("invalid permission operation")
	}
	if s.Kind == "exact" && (!s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.Sub(s.CreatedAt) > 7*24*time.Hour) {
		return fmt.Errorf("exact permission requires bounded expiry")
	}
	return nil
}

func (s DecisionScope) Matches(q DecisionScope, now time.Time) bool {
	if s.Validate() != nil || s.Kind == "once" || !s.RevokedAt.IsZero() || (!s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)) || now.Before(s.CreatedAt) {
		return false
	}
	return (s.Kind != "session" || s.SessionID == q.SessionID) && s.Agent == q.Agent && s.Workspace == q.Workspace && s.ReaderExe == q.ReaderExe && s.RuleID == q.RuleID && s.ResourcePath == q.ResourcePath && s.Operation == q.Operation && s.Destination == q.Destination
}

// MismatchReason explains a previous permission without implying executable
// authenticity or weakening the coordinates checked by Matches.
func (s DecisionScope) MismatchReason(q DecisionScope, now time.Time) string {
	if s.Validate() != nil || !ExactPath(q.Workspace) || !ExactPath(q.ReaderExe) || q.SessionID == "" {
		return "Live session or executable identity is incomplete; choose once."
	}
	if !s.RevokedAt.IsZero() {
		return "The previous permission was revoked."
	}
	if !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt) {
		return "The previous permission expired."
	}
	if s.Kind == "session" && s.SessionID != q.SessionID {
		return "This is a different session from the previous permission."
	}
	if s.Workspace != q.Workspace {
		return "The workspace differs from the previous permission."
	}
	if s.ReaderExe != q.ReaderExe {
		return "The executable path differs from the previous permission."
	}
	if s.Operation != q.Operation {
		return "The operation differs from the previous permission."
	}
	if s.Destination != q.Destination {
		return "The recipient differs from the previous permission."
	}
	return "The saved permission could not be revalidated for this request."
}

// ReadConnectScopes derives coordinates from typed recorded evidence only.
// Incomplete paths, identity or recipients cannot produce reusable permission.
func ReadConnectScopes(f Flag) ([]DecisionScope, error) {
	if f.Rule != "sensitive-read-then-connect" || f.SessionID == "" || !ExactPath(f.Workspace) {
		return nil, fmt.Errorf("incomplete context")
	}
	var reads, connects []EvidenceItem
	for _, e := range f.Evidence {
		if e.Kind == "read" {
			if (e.Sub != "sensitive read" && e.Sub != "agent tool read") || !ExactPath(e.Exe) || !ExactPath(e.Label) {
				return nil, fmt.Errorf("reader or resource unknown")
			}
			reads = append(reads, e)
		}
		if e.Kind == "connect" && e.Sub == "egress" {
			if Endpoint(e.Label) == "" {
				return nil, fmt.Errorf("endpoint unknown")
			}
			connects = append(connects, e)
		}
	}
	if len(reads) == 0 || len(connects) == 0 || len(reads)*len(connects) > 128 {
		return nil, fmt.Errorf("complete bounded read/connect evidence required")
	}
	out := make([]DecisionScope, 0, len(reads)*len(connects))
	for _, r := range reads {
		for _, c := range connects {
			out = append(out, DecisionScope{Agent: f.Agent, SessionID: f.SessionID, Workspace: f.Workspace, ReaderExe: r.Exe, ResourcePath: r.Label, RuleID: f.Rule, Operation: "read-connect", Destination: Endpoint(c.Label), IdentityBasis: "observed-session"})
		}
	}
	return out, nil
}
