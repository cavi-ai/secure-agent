package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/doctor"
	"github.com/cavi-ai/secure-agent/daemon/internal/posture"
)

// DoctorCheck is one self-check verdict. State is pass, fail or skip; Fix is
// a one-line remedy, set only on fail.
type DoctorCheck struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// DoctorSummary counts checks by state.
type DoctorSummary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// DoctorReport is the daemon's verdict on its own coverage: whether hooks,
// file telemetry, collectors and traces produce data, and whether stored
// sessions and events are attributed, paired, priced and retained. Grace is
// true inside the boot window, where steady-state checks skip.
type DoctorReport struct {
	GeneratedAt string           `json:"generated_at"`
	LossReview  DoctorLossReview `json:"loss_review"`
	Version     string           `json:"version"`
	Uptime      string           `json:"uptime"`
	Grace       bool             `json:"grace"`
	Summary     DoctorSummary    `json:"summary"`
	Checks      []DoctorCheck    `json:"checks"` // fixed order; never nil
}

// DoctorLossReview records review of history without clearing live faults.
type DoctorLossReview struct {
	SeenAt  string `json:"seen_at,omitempty"`
	Pending bool   `json:"pending"`
}

// handleDoctor serves the daemon's self-check. Read-level.
//
//	GET /doctor
func (a *API) handleDoctor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, a.doctorReport(time.Now()))
}

// DoctorSeen is when spool loss and bus drops were marked seen.
type DoctorSeen struct {
	SeenAt string `json:"seen_at"`
}

// handleDoctorSeen marks the spool loss and bus drops so far as seen: their
// checks pass until either grows again. The counts stay in status.
//
//	POST /doctor/seen
func (a *API) handleDoctorSeen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.lossSeen == nil {
		http.Error(w, "loss tracking unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now()
	seenAt := now
	// A console acknowledges only the report it displayed. Newer losses
	// remain actionable even if they arrive while the request is in flight.
	if r.Body != nil {
		limitBody(w, r)
		var req DoctorSeen
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != io.EOF {
			at, parseErr := time.Parse(time.RFC3339Nano, req.SeenAt)
			var extra any
			if err != nil || parseErr != nil || at.After(now) || decoder.Decode(&extra) != io.EOF {
				http.Error(w, "Invalid loss acknowledgement", http.StatusBadRequest)
				return
			}
			seenAt = at
		}
	}
	a.lossSeen.Mark(seenAt)
	writeJSON(w, DoctorSeen{SeenAt: seenAt.UTC().Format(time.RFC3339Nano)})
}

func (a *API) doctorReport(now time.Time) DoctorReport {
	rep := doctor.Build(a.doctorFacts(now))
	out := DoctorReport{
		GeneratedAt: rep.GeneratedAt,
		LossReview:  DoctorLossReview(rep.LossReview),
		Version:     rep.Version,
		Uptime:      rep.Uptime,
		Grace:       rep.Grace,
		Summary:     DoctorSummary(rep.Summary),
		Checks:      make([]DoctorCheck, len(rep.Checks)),
	}
	for i, c := range rep.Checks {
		out.Checks[i] = DoctorCheck(c)
	}
	return out
}

func (a *API) doctorFacts(now time.Time) doctor.Facts {
	st := a.evidenceStatus(a.statusFn())
	uptime, _ := time.ParseDuration(st.Uptime)
	f := doctor.Facts{
		Now:          now,
		Boot:         now.Add(-uptime),
		Grace:        uptime < posture.CollectorBootGrace,
		Status:       posture.Status(st),
		ClaudeActive: activeHarness(st, "claude"),
		LossSeen:     a.lossSeen,
	}
	if path, err := claudeSettingsPath(); err == nil {
		f.SettingsKnown = true
		f.HookRegistered = claudeHookRegistered(path)
		f.HookDuplicate = claudeMarketplacePath(path) != "" && nativeClaudeHookAny(path)
	}
	if st.Coverage != nil {
		for _, row := range st.Coverage.Harnesses {
			if row.GuardSupported {
				f.HookHarnesses = append(f.HookHarnesses, row.Name)
				if row.HookLastSeen == "" {
					f.MissingHookHarnesses = append(f.MissingHookHarnesses, row.Name)
				}
			}
		}
	}
	doctor.GatherStoreFacts(&f, a.store)
	if st.UninspectedEgress > 0 {
		for _, r := range a.uninspectedRows(now.Add(-correlate.UninspectedWindow), 200) {
			f.Egress = append(f.Egress, doctor.EgressRow{Agent: r.Agent, Host: r.Host, Infra: r.Infra, AgentKind: r.AgentKind})
		}
	}
	if a.sightings != nil {
		f.SeenByHarness = a.sightings(f.Boot)
	}
	if a.hermes != nil {
		h := a.hermes()
		f.Hermes = &h
	}
	f.ConfigBoot, f.ConfigReload, f.ConfigRestart = a.configProblems()
	return f
}
