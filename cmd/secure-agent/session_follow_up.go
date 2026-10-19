package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxFollowUpRows = 1000

type sessionFollowUpEnvelope struct {
	SessionID  string          `json:"session_id"`
	ObservedAt time.Time       `json:"observed_at"`
	History    json.RawMessage `json:"history"`
	FollowUp   json.RawMessage `json:"follow_up"`
}

type sessionFollowUp struct {
	SchemaVersion   int                     `json:"schema_version"`
	SessionID       string                  `json:"session_id"`
	ObservedAt      time.Time               `json:"observed_at"`
	Partial         *bool                   `json:"partial"`
	Sources         sessionFollowUpSources  `json:"sources"`
	NewerEvidence   []sessionNewerEvidence  `json:"newer_evidence"`
	ProcessActions  []sessionProcessAction  `json:"process_actions"`
	ReportedActions []sessionReportedAction `json:"reported_actions"`
	Permissions     []sessionPermission     `json:"permissions"`
}

type sessionFollowUpSources struct {
	Guards        sessionFollowUpSource `json:"guards"`
	Reviews       sessionFollowUpSource `json:"reviews"`
	Incidents     sessionFollowUpSource `json:"incidents"`
	Interventions sessionFollowUpSource `json:"interventions"`
}

type sessionFollowUpSource struct {
	Available *bool `json:"available"`
	AtLimit   *bool `json:"at_limit"`
	Limit     int   `json:"limit"`
}

type sessionNewerEvidence struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Revision          int64   `json:"revision"`
	DecisionRevision  int64   `json:"decision_revision"`
	EvidenceFlagID    *string `json:"evidence_flag_id"`
	EvidenceAvailable *bool   `json:"evidence_available"`
}

type sessionProcessAction struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Verification string   `json:"verification"`
	VerifiedBy   *string  `json:"verified_by"`
	Limits       []string `json:"limits"`
}

type sessionReportedAction struct {
	IncidentID    string `json:"incident_id"`
	StepID        string `json:"step_id"`
	Title         string `json:"title"`
	Action        string `json:"action"`
	NewerEvidence *bool  `json:"newer_evidence"`
	Verification  string `json:"verification"`
}

type sessionPermission struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	IDs    []string `json:"ids"`
	Title  string   `json:"title"`
	Status string   `json:"status"`
}

func runSessionFollowUp(client *http.Client, arg string, asJSON bool, out io.Writer) error {
	code, body, err := sessionRequest(client, sessionOutcomesURL(arg))
	if err != nil {
		return fmt.Errorf("session follow-up unavailable: %w", err)
	}
	sessionID := arg
	if code == http.StatusNotFound {
		if !utf8.ValidString(arg) {
			return fmt.Errorf("session id prefix must be valid UTF-8")
		}
		if utf8.RuneCountInString(arg) < minSessionPrefix {
			return fmt.Errorf("no session %q (an id prefix needs at least %d characters)", arg, minSessionPrefix)
		}
		sessionID, err = resolveSessionPrefix(client, arg)
		if err != nil {
			return err
		}
		code, body, err = sessionRequest(client, sessionOutcomesURL(sessionID))
		if err != nil {
			return fmt.Errorf("session follow-up unavailable: %w", err)
		}
	}
	if code != http.StatusOK {
		if code == http.StatusNotFound {
			return fmt.Errorf("daemon does not provide session outcomes; use the console or update daemon")
		}
		return fmt.Errorf("session follow-up unavailable (%d)", code)
	}
	var envelope sessionFollowUpEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || envelope.SessionID == "" || envelope.ObservedAt.IsZero() || !isJSONObject(envelope.History) {
		return fmt.Errorf("invalid session follow-up response: malformed envelope")
	}
	if envelope.SessionID != sessionID {
		return fmt.Errorf("invalid session follow-up response: session identity mismatch")
	}
	if len(envelope.FollowUp) == 0 || bytes.Equal(bytes.TrimSpace(envelope.FollowUp), []byte("null")) {
		return fmt.Errorf("daemon does not provide structured session follow-up; use the console or update daemon")
	}
	followUp, err := decodeSessionFollowUp(envelope.FollowUp)
	if err != nil {
		return err
	}
	if err := validateSessionFollowUp(followUp, sessionID, envelope.ObservedAt); err != nil {
		return err
	}
	if asJSON {
		encoded, err := json.Marshal(followUp)
		if err != nil {
			return fmt.Errorf("encode session follow-up: %w", err)
		}
		_, err = fmt.Fprintf(out, "%s\n", encoded)
		return err
	}
	return renderSessionFollowUp(out, followUp)
}

func sessionOutcomesURL(id string) string {
	return "http://unix/sessions/" + url.PathEscape(id) + "/outcomes"
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 1 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func decodeSessionFollowUp(raw json.RawMessage) (sessionFollowUp, error) {
	var followUp sessionFollowUp
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&followUp); err != nil {
		return sessionFollowUp{}, fmt.Errorf("invalid session follow-up: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return sessionFollowUp{}, fmt.Errorf("invalid session follow-up: trailing data")
	}
	if followUp.SchemaVersion != 1 {
		return sessionFollowUp{}, fmt.Errorf("unsupported session follow-up schema; use the console or update daemon")
	}
	return followUp, nil
}

func validateSessionFollowUp(followUp sessionFollowUp, sessionID string, observedAt time.Time) error {
	if !utf8.ValidString(sessionID) || followUp.SessionID == "" || followUp.SessionID != sessionID {
		return fmt.Errorf("invalid session follow-up: session identity mismatch")
	}
	if followUp.ObservedAt.IsZero() || !followUp.ObservedAt.Equal(observedAt) || followUp.Partial == nil {
		return fmt.Errorf("invalid session follow-up: observation metadata is invalid")
	}
	sources := []struct {
		name   string
		source sessionFollowUpSource
	}{
		{"guards", followUp.Sources.Guards}, {"reviews", followUp.Sources.Reviews},
		{"incidents", followUp.Sources.Incidents}, {"interventions", followUp.Sources.Interventions},
	}
	partial := false
	for _, source := range sources {
		if source.source.Available == nil || source.source.AtLimit == nil || source.source.Limit < 1 || source.source.Limit > maxFollowUpRows {
			return fmt.Errorf("invalid session follow-up: source %s is incomplete", source.name)
		}
		if !*source.source.Available || *source.source.AtLimit {
			partial = true
		}
	}
	if *followUp.Partial != partial {
		return fmt.Errorf("invalid session follow-up: partial state conflicts with source availability")
	}
	if followUp.NewerEvidence == nil || followUp.ProcessActions == nil || followUp.ReportedActions == nil || followUp.Permissions == nil ||
		len(followUp.NewerEvidence) > maxFollowUpRows || len(followUp.ProcessActions) > maxFollowUpRows || len(followUp.Permissions) > maxFollowUpRows {
		return fmt.Errorf("invalid session follow-up: missing or oversized groups")
	}
	for _, item := range followUp.NewerEvidence {
		if item.ID == "" || item.Title == "" || item.Revision < 1 || item.DecisionRevision < 1 || item.EvidenceFlagID == nil || item.EvidenceAvailable == nil || (*item.EvidenceAvailable && *item.EvidenceFlagID == "") {
			return fmt.Errorf("invalid session follow-up: malformed newer-evidence item")
		}
	}
	for _, item := range followUp.ProcessActions {
		if item.ID == "" || item.Kind == "" || item.Status == "" || item.Verification == "" || item.VerifiedBy == nil || item.Limits == nil || len(item.Limits) > maxFollowUpRows {
			return fmt.Errorf("invalid session follow-up: malformed process-action item")
		}
	}
	for _, item := range followUp.ReportedActions {
		if item.IncidentID == "" || item.StepID == "" || item.Title == "" || item.Action == "" || item.NewerEvidence == nil || item.Verification != "not_verified" {
			return fmt.Errorf("invalid session follow-up: malformed reported-action item")
		}
	}
	for _, item := range followUp.Permissions {
		if item.ID == "" || (item.Kind != "review" && item.Kind != "guard") || item.Title == "" || item.Status != "unknown" || item.IDs == nil || len(item.IDs) == 0 || len(item.IDs) > maxFollowUpRows {
			return fmt.Errorf("invalid session follow-up: malformed permission item")
		}
		seen := make(map[string]bool, len(item.IDs))
		for _, id := range item.IDs {
			if id == "" || seen[id] {
				return fmt.Errorf("invalid session follow-up: malformed permission scope IDs")
			}
			seen[id] = true
		}
	}
	return nil
}

func renderSessionFollowUp(out io.Writer, followUp sessionFollowUp) error {
	if _, err := fmt.Fprintf(out, "Session %s\nObserved at %s\n", terminalSafe(followUp.SessionID), followUp.ObservedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if *followUp.Partial {
		if _, err := io.WriteString(out, "Partial retained result; other work may be absent.\n"); err != nil {
			return err
		}
	}
	for _, source := range []struct {
		name   string
		source sessionFollowUpSource
	}{
		{"Guards", followUp.Sources.Guards}, {"Reviews", followUp.Sources.Reviews},
		{"Incidents", followUp.Sources.Incidents}, {"Interventions", followUp.Sources.Interventions},
	} {
		if !*source.source.Available {
			if _, err := fmt.Fprintf(out, "Source warning: %s unavailable; some follow-up may be missing.\n", source.name); err != nil {
				return err
			}
		}
		if *source.source.AtLimit {
			if _, err := fmt.Fprintf(out, "Source warning: %s reached its %d-row limit; more follow-up may be omitted.\n", source.name, source.source.Limit); err != nil {
				return err
			}
		}
	}
	groups := [][]string{}
	groups = append(groups, []string{"New evidence after a saved decision", formatNewerEvidence(followUp.NewerEvidence)})
	groups = append(groups, []string{"Actions to check", formatProcessActions(followUp.ProcessActions)})
	groups = append(groups, []string{"Reported incident actions", formatReportedActions(followUp.ReportedActions)})
	groups = append(groups, []string{"Permissions from decisions", formatPermissions(followUp.Permissions)})
	count := len(followUp.NewerEvidence) + len(followUp.ProcessActions) + len(followUp.ReportedActions) + len(followUp.Permissions)
	if count == 0 {
		if _, err := io.WriteString(out, "No follow-up recorded in retained history. This is not a safety verdict or task-completion result.\n"); err != nil {
			return err
		}
	}
	if len(followUp.Permissions) > 0 {
		if _, err := io.WriteString(out, "Current permission status was not read; inspect before relying on access.\n"); err != nil {
			return err
		}
	}
	for _, group := range groups {
		if _, err := fmt.Fprintf(out, "\n%s:\n%s", group[0], group[1]); err != nil {
			return err
		}
	}
	return nil
}

func formatNewerEvidence(rows []sessionNewerEvidence) string {
	if len(rows) == 0 {
		return "  None recorded in retained history.\n"
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, "  - %s · revision %d; decision revision %d", terminalSafe(row.Title), row.Revision, row.DecisionRevision)
		if *row.EvidenceAvailable {
			fmt.Fprintf(&b, " · evidence %s", terminalSafe(*row.EvidenceFlagID))
		} else {
			b.WriteString(" · source evidence unavailable")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func formatProcessActions(rows []sessionProcessAction) string {
	if len(rows) == 0 {
		return "  None recorded in retained history.\n"
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, "  - %s · %s · status %s · verification %s", terminalSafe(row.Kind), terminalSafe(row.ID), terminalSafe(row.Status), terminalSafe(row.Verification))
		if *row.VerifiedBy != "" {
			fmt.Fprintf(&b, " · verified by %s", terminalSafe(*row.VerifiedBy))
		}
		if len(row.Limits) > 0 {
			fmt.Fprintf(&b, " · limits: %s", terminalSafe(strings.Join(row.Limits, "; ")))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func formatReportedActions(rows []sessionReportedAction) string {
	if len(rows) == 0 {
		return "  None recorded in retained history.\n"
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, "  - %s · %s · %s · verification not verified", terminalSafe(row.IncidentID), terminalSafe(row.Title), terminalSafe(row.Action))
		if *row.NewerEvidence {
			b.WriteString(" · newer evidence exists")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func formatPermissions(rows []sessionPermission) string {
	if len(rows) == 0 {
		return "  None recorded in retained history.\n"
	}
	var b strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&b, "  - %s · %s · scope IDs %s · status unknown (not read)\n", terminalSafe(row.Title), terminalSafe(row.Kind), terminalSafe(strings.Join(row.IDs, ", ")))
	}
	return b.String()
}

func terminalSafe(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			if r <= 0xffff {
				fmt.Fprintf(&b, "\\u%04X", r)
			} else {
				fmt.Fprintf(&b, "\\U%08X", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
