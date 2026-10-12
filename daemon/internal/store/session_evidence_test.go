package store

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestSessionFindingsSelectsNewestSessionRows(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, id := range []string{"owned", "other"} {
		if err := s.UpsertSession(model.Session{ID: id, StartedAt: base, Status: model.SessionEnded}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PutFlag(model.Flag{ID: "other", SessionID: "other", Rule: "sensitive-read-then-connect", Severity: 3, TS: base.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for i := range 21 {
		if _, err := s.PutFlag(model.Flag{ID: fmt.Sprintf("%02d", i), SessionID: "owned", Rule: "sensitive-read-then-connect", Severity: 3, TS: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	if !s.AcknowledgeFlag("20") {
		t.Fatal("acknowledge newest finding")
	}
	got, err := s.SessionFindings("owned")
	if err != nil || got.Session.ID != "owned" || !got.Truncated || len(got.Findings) != 20 {
		t.Fatalf("bounded findings: %+v %v", got, err)
	}
	if got.Findings[0].ID != "20" || got.Findings[19].ID != "01" || got.Findings[0].Assessment.ReviewState != "reviewed" || got.Findings[1].Assessment.ReviewState != "unreviewed" || got.Findings[0].Assessment.ResidualRisk == "" {
		t.Fatalf("order or assessment: %+v", got.Findings)
	}
	for _, f := range got.Findings {
		if f.ID == "other" || f.ID == "00" {
			t.Fatalf("finding crossed the session or the cap: %+v", got.Findings)
		}
	}
}

func TestSessionFindingsEmptySliceAndReadFailures(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.UpsertSession(model.Session{ID: "owned", StartedAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionFindings("owned")
	if err != nil || got.Findings == nil || len(got.Findings) != 0 || got.Truncated {
		t.Fatalf("empty findings: %+v %v", got, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE flags RENAME TO flags_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionFindings("missing"); !errors.Is(err, ErrSessionFindingsMissing) {
		t.Fatalf("missing session required findings: %v", err)
	}
	if _, err := s.SessionFindings("owned"); !errors.Is(err, ErrSessionFindingsRead) {
		t.Fatalf("findings failure: %v", err)
	}
	if _, err := s.db.Exec(`ALTER TABLE flags_hidden RENAME TO flags`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutFlag(model.Flag{ID: "flag", SessionID: "owned", Rule: "sensitive-read-then-connect", Severity: 3, TS: at}); err != nil {
		t.Fatal(err)
	}
	got, err = s.SessionFindings("owned")
	if err != nil || len(got.Findings) != 1 || got.Findings[0].ID != "flag" {
		t.Fatalf("findings did not recover: %+v %v", got, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE sessions RENAME TO sessions_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE flags RENAME TO flags_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionFindings("owned"); !errors.Is(err, ErrSessionFindingsIdentity) {
		t.Fatalf("identity failure read findings: %v", err)
	}
}

func TestSessionOutcomeResultChecksIdentityBeforeReceipts(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	history, found, err := s.SessionOutcomeResult("missing")
	if err != nil || found || len(history.Reviews) != 0 {
		t.Fatalf("missing session: %+v %v %v", history, found, err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.UpsertSession(model.Session{ID: "owned", StartedAt: at, Status: model.SessionEnded}); err != nil {
		t.Fatal(err)
	}
	history, found, err = s.SessionOutcomeResult("owned")
	if err != nil || !found || !history.Evidence.Reviews.Available || !history.Evidence.Incidents.Available || !history.Evidence.Interventions.Available || history.Reviews == nil {
		t.Fatalf("empty receipts: %+v %v %v", history, found, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE sessions RENAME TO sessions_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, found, err = s.SessionOutcomeResult("owned"); err == nil || found {
		t.Fatalf("identity failure returned receipts: %v %v", found, err)
	}
}
