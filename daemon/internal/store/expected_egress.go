package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const expectedEgressSchema = `CREATE TABLE IF NOT EXISTS expected_egress_rules (
 id TEXT PRIMARY KEY, agent TEXT NOT NULL, kind TEXT NOT NULL,
 host TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL,
 exe_path TEXT NOT NULL, harness TEXT NOT NULL, workspace TEXT NOT NULL,
 rationale TEXT NOT NULL, created_by TEXT NOT NULL,
 created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_expected_egress_match ON expected_egress_rules(agent,kind,revoked_at);`

type ExpectedEgressRule struct {
	ID        string     `json:"id"`
	Agent     string     `json:"agent"`
	Kind      string     `json:"kind"`
	Host      string     `json:"host,omitempty"`
	Protocol  string     `json:"protocol,omitempty"`
	ExePath   string     `json:"exe_path,omitempty"`
	Harness   string     `json:"harness,omitempty"`
	Workspace string     `json:"workspace,omitempty"`
	Rationale string     `json:"rationale"`
	CreatedBy string     `json:"created_by"`
	Port      int        `json:"port,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ErrInvalidExpectedEgressRule identifies rejected rule input.
var ErrInvalidExpectedEgressRule = errors.New("invalid expected egress rule")

func canonicalExpectedRule(rule ExpectedEgressRule) (ExpectedEgressRule, error) {
	rule.Agent = strings.TrimSpace(rule.Agent)
	if rule.Agent == "" || len(rule.Agent) > 64 || strings.ContainsAny(rule.Agent, "/?#@ \t\r\n") {
		return rule, errors.New("invalid agent")
	}
	rule.CreatedBy = "local-operator"
	rule.Rationale = "Operator marked observed egress expected"
	switch rule.Kind {
	case "destination":
		var err error
		rule.Host, err = normalizeEgressHost(rule.Host)
		if err != nil {
			return rule, err
		}
		ip := net.ParseIP(rule.Host)
		if rule.Host == "localhost" || strings.HasSuffix(rule.Host, ".localhost") || ip != nil && ip.IsLoopback() {
			return rule, errors.New("local destination cannot be expected")
		}
		rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
		if rule.Protocol != "tcp" && rule.Protocol != "udp" || rule.Port < 1 || rule.Port > 65535 {
			return rule, errors.New("invalid destination transport")
		}
		rule.ExePath, rule.Harness, rule.Workspace = "", "", ""
	case "scope":
		scope := normalizeEgressScope(EgressScope{Agent: rule.Agent, ExePath: rule.ExePath, Harness: rule.Harness, Workspace: rule.Workspace})
		if !scope.Complete() {
			return rule, errors.New("incomplete activity scope")
		}
		rule.ExePath, rule.Harness, rule.Workspace = scope.ExePath, scope.Harness, scope.Workspace
		rule.Host, rule.Protocol, rule.Port = "", "", 0
	default:
		return rule, errors.New("invalid expected-egress kind")
	}
	key, _ := json.Marshal([]any{rule.Agent, rule.Kind, rule.Host, rule.Protocol, rule.Port, rule.ExePath, rule.Harness, rule.Workspace})
	sum := sha256.Sum256(key)
	rule.ID = hex.EncodeToString(sum[:16])
	return rule, nil
}

// validateExpectedRuleIdentity checks the key fields written by the rule creator.
func validateExpectedRuleIdentity(rule ExpectedEgressRule) error {
	canonical, err := canonicalExpectedRule(rule)
	if err != nil || canonical.ID != rule.ID || canonical.Agent != rule.Agent ||
		canonical.Host != rule.Host || canonical.Protocol != rule.Protocol || canonical.Port != rule.Port ||
		canonical.ExePath != rule.ExePath || canonical.Harness != rule.Harness || canonical.Workspace != rule.Workspace {
		return errors.New("invalid stored expected egress rule identity")
	}
	return nil
}

func scanExpectedRule(scanner interface{ Scan(...any) error }) (ExpectedEgressRule, error) {
	var r ExpectedEgressRule
	var created string
	var revoked sql.NullString
	err := scanner.Scan(&r.ID, &r.Agent, &r.Kind, &r.Host, &r.Protocol, &r.Port, &r.ExePath, &r.Harness, &r.Workspace, &r.Rationale, &r.CreatedBy, &created, &revoked)
	if err != nil {
		return r, err
	}
	if err := validateExpectedRuleIdentity(r); err != nil {
		return ExpectedEgressRule{}, err
	}
	r.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return r, err
	}
	if revoked.Valid {
		t, err := time.Parse(time.RFC3339Nano, revoked.String)
		if err != nil {
			return r, err
		}
		r.RevokedAt = &t
	}
	return r, nil
}

func (s *Store) CreateExpectedEgressRule(rule ExpectedEgressRule) (out ExpectedEgressRule, writeErr error) {
	var err error
	rule, err = canonicalExpectedRule(rule)
	if err != nil {
		return rule, fmt.Errorf("%w: %v", ErrInvalidExpectedEgressRule, err)
	}
	defer func() { s.noteWrite("expected egress create", writeErr) }()
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	var existing ExpectedEgressRule
	existing, err = scanExpectedRule(s.db.QueryRow(`SELECT id,agent,kind,host,protocol,port,exe_path,harness,workspace,rationale,created_by,created_at,revoked_at FROM expected_egress_rules WHERE id=?`, rule.ID))
	if err == nil && existing.RevokedAt == nil {
		return existing, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return rule, err
	}
	rule.CreatedAt = time.Now().UTC()
	_, err = s.db.Exec(`INSERT INTO expected_egress_rules(id,agent,kind,host,protocol,port,exe_path,harness,workspace,rationale,created_by,created_at,revoked_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at, revoked_at=NULL`,
		rule.ID, rule.Agent, rule.Kind, rule.Host, rule.Protocol, rule.Port, rule.ExePath, rule.Harness, rule.Workspace, rule.Rationale, rule.CreatedBy, rule.CreatedAt.Format(time.RFC3339Nano))
	return rule, err
}

func (s *Store) RevokeExpectedEgressRule(id string) (writeErr error) {
	if id == "" {
		return errors.New("missing rule id")
	}
	defer func() {
		if !errors.Is(writeErr, sql.ErrNoRows) {
			s.noteWrite("expected egress revoke", writeErr)
		}
	}()
	s.egressMu.Lock()
	defer s.egressMu.Unlock()
	result, err := s.db.Exec(`UPDATE expected_egress_rules SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListExpectedEgressRules() []ExpectedEgressRule {
	rules, _ := s.ListExpectedEgressRulesResult()
	return rules
}

// ListExpectedEgressRulesResult rejects incomplete rule lists.
func (s *Store) ListExpectedEgressRulesResult() (out []ExpectedEgressRule, readErr error) {
	defer func() { s.noteRead("expected egress rules", readErr) }()
	out = make([]ExpectedEgressRule, 0)
	read := func(query string) error {
		rows, err := s.db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanExpectedRule(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}
	columns := `SELECT id,agent,kind,host,protocol,port,exe_path,harness,workspace,rationale,created_by,created_at,revoked_at FROM expected_egress_rules`
	if err := read(columns + ` WHERE revoked_at IS NULL ORDER BY created_at DESC,id DESC`); err != nil {
		return nil, err
	}
	if err := read(columns + ` WHERE revoked_at IS NOT NULL ORDER BY created_at DESC,id DESC LIMIT 500`); err != nil {
		return nil, err
	}
	return out, nil
}

// ExpectedEgressMatch only classifies informational candidates. It is never
// consulted by the proxy, guard, correlator, incident, or flag paths.
func (s *Store) ExpectedEgressMatch(o EgressObservation) bool {
	return s.ExpectedEgressMatchingRuleID(o) != ""
}

// ExpectedEgressMatchingRuleID returns the active rule that explains an
// episode, preferring the exact destination over a broader activity scope.
func (s *Store) ExpectedEgressMatchingRuleID(o EgressObservation) string {
	var err error
	o.Host, err = normalizeEgressHost(o.Host)
	if err != nil {
		return ""
	}
	o.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	return s.ExpectedEgressMatcher()(EgressEpisode{Scope: normalizeEgressScope(o.Scope), Host: o.Host, Protocol: o.Protocol, Port: o.Port})
}

// ExpectedEgressMatcher reads the active rules once and answers
// ExpectedEgressMatchingRuleID for any number of stored episodes, whose
// scope, host and protocol were normalized when they were recorded.
func (s *Store) ExpectedEgressMatcher() func(EgressEpisode) string {
	match, err := s.ExpectedEgressMatcherResult()
	if err != nil {
		return func(EgressEpisode) string { return "" }
	}
	return match
}

// ExpectedEgressMatcherResult rejects failed reads before classifying episodes.
func (s *Store) ExpectedEgressMatcherResult() (match func(EgressEpisode) string, readErr error) {
	defer func() { s.noteRead("expected egress matcher", readErr) }()
	var rules []ExpectedEgressRule
	rows, err := s.db.Query(`SELECT id,agent,kind,host,protocol,port,exe_path,harness,workspace FROM expected_egress_rules
	 WHERE revoked_at IS NULL ORDER BY CASE WHEN kind='destination' THEN 0 ELSE 1 END, created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ExpectedEgressRule
		if err := rows.Scan(&r.ID, &r.Agent, &r.Kind, &r.Host, &r.Protocol, &r.Port, &r.ExePath, &r.Harness, &r.Workspace); err != nil {
			return nil, err
		}
		if err := validateExpectedRuleIdentity(r); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return func(e EgressEpisode) string {
		if e.Scope.Agent == "" {
			return ""
		}
		for _, r := range rules {
			if r.Agent != e.Scope.Agent {
				continue
			}
			switch r.Kind {
			case "destination":
				if r.Host == e.Host && r.Protocol == e.Protocol && r.Port == e.Port {
					return r.ID
				}
			case "scope":
				if e.Scope.Complete() && r.ExePath == e.Scope.ExePath && r.Harness == e.Scope.Harness && r.Workspace == e.Scope.Workspace {
					return r.ID
				}
			}
		}
		return ""
	}, nil
}
