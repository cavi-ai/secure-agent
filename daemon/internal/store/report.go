package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// ReportCount is one grouped count in a SessionReport: a tool, a file path, a
// remote host.
type ReportCount struct {
	Key        string `json:"key"`
	Count      int    `json:"count"`
	Errors     int    `json:"errors,omitempty"`      // tools: calls with tool_status "error"
	DurationMs int64  `json:"duration_ms,omitempty"` // tools: summed call duration
}

// ReportModel is one model's usage in a SessionReport.
type ReportModel struct {
	Model     string  `json:"model"`
	Calls     int     `json:"calls"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Unpriced  int     `json:"unpriced_calls"` // calls with cost 0 (model not in the pricing table)
}

// ReportLine is one timestamped line in a SessionReport list.
type ReportLine struct {
	TS         string `json:"ts"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Status     string `json:"status,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// SessionReport is what one session did: its tools, models, spend, files,
// hosts, guard decisions, findings and secret-rule hits, plus the opening of
// its timeline. It carries names, paths, hosts, model ids, rule ids and
// counts — never content.
type SessionReport struct {
	Evidence               *ReportEvidence             `json:"evidence,omitempty"`
	Reviews                []model.ReviewRecord        `json:"reviews"`
	Incidents              []model.IncidentReport      `json:"incidents"`
	IncidentsAvailable     bool                        `json:"incidents_available"`
	Interventions          []model.InterventionReceipt `json:"interventions"`
	InterventionsAvailable bool                        `json:"interventions_available"`
	Session                model.Session               `json:"session"`
	DurationS              int64                       `json:"duration_s"` // started → ended, or → last seen
	Events                 int                         `json:"events"`     // events aggregated (at most reportEventCap)
	Turns                  int                         `json:"turns"`
	ToolCalls              int                         `json:"tool_calls"`
	ModelCalls             int                         `json:"model_calls"`
	TokensIn               int64                       `json:"tokens_in"`
	TokensOut              int64                       `json:"tokens_out"`
	CostUSD                float64                     `json:"cost_usd"`
	Unpriced               int                         `json:"unpriced_calls"`
	Tools                  []ReportCount               `json:"tools"`       // by count desc
	Models                 []ReportModel               `json:"models"`      // by cost desc
	Files                  []ReportCount               `json:"files"`       // file open/write/delete by path, count desc, at most ReportTopN
	Hosts                  []ReportCount               `json:"hosts"`       // connections by remote host, count desc, at most ReportTopN
	Guard                  []ReportLine                `json:"guard"`       // guard prompts and resolutions
	SecretHits             []ReportLine                `json:"secret_hits"` // label = rule id, status = detection layer
	Flags                  []model.Flag                `json:"flags"`
	Timeline               []ReportLine                `json:"timeline"` // oldest first, at most reportTimelineCap
}

const (
	reportEventCap    = 20000
	reportTimelineCap = 500
	reportFlagLimit   = 1000
)

// ReportTopN caps a SessionReport's Files and Hosts lists.
const ReportTopN = 50

// SessionReport aggregates one session's events oldest-first. ok is false
// when no session row has this id. Every slice is non-nil.
func (s *Store) SessionReport(id string) (SessionReport, bool) {
	rep, ok, _ := s.SessionReportResult(id)
	return rep, ok
}

// SessionReportResult distinguishes unavailable identity from a missing session.
// Source failures retain independently readable sections with explicit limits.
func (s *Store) SessionReportResult(id string) (_ SessionReport, _ bool, readErr error) {
	defer func() { s.noteRead("session reports", readErr) }()
	sess, ok, err := s.GetSessionResult(id)
	if err != nil {
		return SessionReport{}, false, err
	}
	if !ok {
		return SessionReport{}, false, nil
	}
	rep := SessionReport{
		Session:    sess,
		Tools:      []ReportCount{},
		Models:     []ReportModel{},
		Files:      []ReportCount{},
		Hosts:      []ReportCount{},
		Guard:      []ReportLine{},
		SecretHits: []ReportLine{},
		Flags:      []model.Flag{},
		Timeline:   []ReportLine{},
		Reviews:    []model.ReviewRecord{},
		Evidence:   &ReportEvidence{},
	}
	end := sess.LastSeenAt
	if sess.EndedAt != nil {
		end = *sess.EndedAt
	}
	if d := end.Sub(sess.StartedAt); d > 0 && !sess.StartedAt.IsZero() {
		rep.DurationS = int64(d / time.Second)
	}

	tools := map[string]*ReportCount{}
	models := map[string]*ReportModel{}
	files := map[string]int{}
	hosts := map[string]int{}
	events, eventErr := s.sessionEventsOldestFirst(id)
	rep.Evidence.Events = ReportSourceEvidence{Available: eventErr == nil, AtLimit: len(events) >= reportEventCap, Limit: reportEventCap}
	for _, e := range events {
		rep.Events++
		ts := e.TS.UTC().Format(time.RFC3339)
		switch e.Kind {
		case event.KindTurn:
			rep.Turns++
		case event.KindToolCall:
			rep.ToolCalls++
			name := orUnknown(e.ToolName)
			t := tools[name]
			if t == nil {
				t = &ReportCount{Key: name}
				tools[name] = t
			}
			t.Count++
			t.DurationMs += e.DurationMs
			if e.ToolStatus == "error" {
				t.Errors++
			}
		case event.KindModelCall:
			rep.ModelCalls++
			rep.TokensIn += e.TokensIn
			rep.TokensOut += e.TokensOut
			rep.CostUSD += e.CostUSD
			if math.IsInf(rep.CostUSD, 0) || math.IsNaN(rep.CostUSD) {
				return SessionReport{}, false, errors.New("nonfinite session report cost")
			}
			name := orUnknown(e.Model)
			m := models[name]
			if m == nil {
				m = &ReportModel{Model: name}
				models[name] = m
			}
			m.Calls++
			m.TokensIn += e.TokensIn
			m.TokensOut += e.TokensOut
			m.CostUSD += e.CostUSD
			if math.IsInf(m.CostUSD, 0) || math.IsNaN(m.CostUSD) {
				return SessionReport{}, false, errors.New("nonfinite session model cost")
			}
			if e.CostUSD == 0 {
				rep.Unpriced++
				m.Unpriced++
			}
		case event.KindFileOpen, event.KindFileWrite, event.KindFileDelete:
			if e.Path != "" {
				files[e.Path]++
			}
		case event.KindConnOpen:
			if e.RemoteHost != "" {
				hosts[e.RemoteHost]++
			}
		case event.KindGuardPrompt, event.KindGuardResolved:
			rep.Guard = append(rep.Guard, ReportLine{TS: ts, Kind: e.Kind.String(), Label: e.Detail})
		case event.KindTranscriptHit:
			rule, layer := splitSecretHit(e.Detail)
			rep.SecretHits = append(rep.SecretHits, ReportLine{TS: ts, Kind: e.Kind.String(), Label: rule, Status: layer})
		}
		if len(rep.Timeline) < reportTimelineCap {
			rep.Timeline = append(rep.Timeline, timelineLine(e, ts))
		}
	}

	for _, t := range tools {
		rep.Tools = append(rep.Tools, *t)
	}
	sort.Slice(rep.Tools, func(i, j int) bool {
		a, b := rep.Tools[i], rep.Tools[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Key < b.Key
	})
	for _, m := range models {
		rep.Models = append(rep.Models, *m)
	}
	sort.Slice(rep.Models, func(i, j int) bool {
		a, b := rep.Models[i], rep.Models[j]
		if a.CostUSD != b.CostUSD {
			return a.CostUSD > b.CostUSD
		}
		if a.Calls != b.Calls {
			return a.Calls > b.Calls
		}
		return a.Model < b.Model
	})
	rep.Files = topCounts(files, ReportTopN)
	rep.Hosts = topCounts(hosts, ReportTopN)
	var flagErr error
	rep.Flags, flagErr = s.QueryFlagsResult(FlagFilter{SessionID: id, Limit: reportFlagLimit})
	rep.Evidence.Flags = ReportSourceEvidence{Available: flagErr == nil, AtLimit: len(rep.Flags) >= reportFlagLimit, Limit: reportFlagLimit}
	page, reviewErr := s.ListSessionFindingReviews(id)
	if reviewErr == nil && !page.Degraded {
		rep.Reviews = page.Reviews
		for i := range rep.Reviews {
			// An export is history, not a current permission/action surface.
			rep.Reviews[i].AvailableScopes = nil
		}
	}
	rep.Evidence.Reviews = ReportSourceEvidence{Available: reviewErr == nil && !page.Degraded, AtLimit: len(rep.Reviews) >= 100, Limit: 100}
	var interventionErr error
	rep.Interventions, interventionErr = s.RecentInterventions(id, 200)
	rep.InterventionsAvailable = interventionErr == nil
	rep.Evidence.Interventions = ReportSourceEvidence{Available: interventionErr == nil, AtLimit: len(rep.Interventions) >= 200, Limit: 200}
	var incidentErr error
	rep.Incidents, incidentErr = s.SessionIncidents(id)
	rep.IncidentsAvailable = incidentErr == nil
	rep.Evidence.Incidents = ReportSourceEvidence{Available: incidentErr == nil, AtLimit: len(rep.Incidents) >= 100, Limit: 100}
	if rep.Flags == nil {
		rep.Flags = []model.Flag{}
	}
	if rep.Incidents == nil {
		rep.Incidents = []model.IncidentReport{}
	}
	if rep.Interventions == nil {
		rep.Interventions = []model.InterventionReceipt{}
	}
	return rep, true, nil
}

// sessionEventsOldestFirst reads up to reportEventCap of one session's events
// in time order (insertion order breaks ties).
func (s *Store) sessionEventsOldestFirst(id string) (out []event.Event, readErr error) {
	defer func() { s.noteRead("session report events", readErr) }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT kind, ts, COALESCE(path,''), COALESCE(remote_host,''), COALESCE(detail,''), tool, tool_status, duration_ms, model, tokens_in, tokens_out, cost_usd
		FROM events WHERE session_id = ? ORDER BY julianday(ts) ASC, id ASC LIMIT ?`, id, reportEventCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out = []event.Event{}
	for rows.Next() {
		var e event.Event
		var kind int
		var ts string
		var tool, toolStatus, modelName sql.NullString
		var durMs, tokIn, tokOut sql.NullInt64
		var cost sql.NullFloat64
		if err := rows.Scan(&kind, &ts, &e.Path, &e.RemoteHost, &e.Detail,
			&tool, &toolStatus, &durMs, &modelName, &tokIn, &tokOut, &cost); err != nil {
			return nil, err
		}
		e.Kind = event.Kind(kind)
		e.TS, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, errors.New("invalid session event timestamp")
		}
		if math.IsInf(cost.Float64, 0) || math.IsNaN(cost.Float64) {
			return nil, errors.New("nonfinite session report event cost")
		}
		e.ToolName, e.ToolStatus, e.Model = tool.String, toolStatus.String, modelName.String
		e.DurationMs, e.TokensIn, e.TokensOut, e.CostUSD = durMs.Int64, tokIn.Int64, tokOut.Int64, cost.Float64
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

// timelineLine labels an event by the first identity it carries: tool, model,
// path, host, then detail.
func timelineLine(e event.Event, ts string) ReportLine {
	label := e.Detail
	for _, v := range []string{e.ToolName, e.Model, e.Path, e.RemoteHost} {
		if v != "" {
			label = v
			break
		}
	}
	line := ReportLine{TS: ts, Kind: e.Kind.String(), Label: label}
	if e.Kind == event.KindToolCall {
		line.Status, line.DurationMs = e.ToolStatus, e.DurationMs
	}
	return line
}

// splitSecretHit reads a transcript-hit detail "<harness>:<layer>:<rule>" as
// (rule, layer). Any other shape is returned whole as the rule.
func splitSecretHit(detail string) (rule, layer string) {
	parts := strings.SplitN(detail, ":", 3)
	if len(parts) == 3 && parts[2] != "" {
		return parts[2], parts[1]
	}
	return detail, ""
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// topCounts orders a key→count map by count desc, then key, keeping n.
func topCounts(m map[string]int, n int) []ReportCount {
	out := make([]ReportCount, 0, len(m))
	for k, c := range m {
		out = append(out, ReportCount{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
