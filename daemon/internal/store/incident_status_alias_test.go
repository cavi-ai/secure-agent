package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestIncidentStatusFollowsFlagListAliasAndExactID(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC()
	if err := s.PutIncident(model.IncidentReport{
		ID: "canonical", FlagID: "opening", Rule: "rule", SessionID: "sess", Subject: "subj", Timestamp: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AggregateIntoIncident("canonical", "listed", now.Add(time.Second)); !ok {
		t.Fatal("could not aggregate listed flag")
	}
	var flagID, flagIDs string
	if err := s.db.QueryRow(`SELECT flag_id, flag_ids FROM incidents WHERE id='canonical'`).Scan(&flagID, &flagIDs); err != nil {
		t.Fatal(err)
	}
	if flagID == "listed" || !strings.Contains(flagIDs, `"listed"`) {
		t.Fatalf("listed flag is not only in flag_ids: flag_id=%q flag_ids=%s", flagID, flagIDs)
	}

	wf, updated, err := s.SetIncidentStatusResult("listed", "acknowledged", "")
	if err != nil || !updated || wf.Status != "acknowledged" || wf.AcknowledgedAt == "" {
		t.Fatalf("ack by flag_ids alias: %+v updated=%v err=%v", wf, updated, err)
	}
	if got, err := s.GetIncident("listed"); err != nil || got.ID != "canonical" {
		t.Fatalf("alias lookup: %+v %v", got, err)
	}
	if id, found, err := s.IncidentIDForFlagResult("listed"); err != nil || !found || id != "canonical" {
		t.Fatalf("alias link: %q found=%v err=%v", id, found, err)
	}
	stored, found := s.IncidentStatus("canonical")
	if !found || stored.Status != "acknowledged" {
		t.Fatalf("canonical after ack: %+v found=%v", stored, found)
	}

	wf, updated, err = s.SetIncidentStatusResult("listed", "resolved", "rotated")
	if err != nil || !updated || wf.Status != "resolved" || wf.ResolutionNote != "rotated" {
		t.Fatalf("resolve by flag_ids alias: %+v updated=%v err=%v", wf, updated, err)
	}
	stored, found = s.IncidentStatus("canonical")
	if !found || stored.Status != "resolved" || stored.ResolutionNote != "rotated" {
		t.Fatalf("canonical after resolve: %+v found=%v", stored, found)
	}

	if err := s.PutIncident(model.IncidentReport{
		ID: "listed", FlagID: "other-opening", Timestamp: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetIncident("listed"); err != nil || got.ID != "listed" {
		t.Fatalf("exact id shadowed by alias: %+v %v", got, err)
	}
	if id, found, err := s.IncidentIDForFlagResult("listed"); err != nil || !found || id != "listed" {
		t.Fatalf("exact id link: %q found=%v err=%v", id, found, err)
	}
	wf, updated, err = s.SetIncidentStatusResult("listed", "acknowledged", "")
	if err != nil || !updated || wf.Status != "acknowledged" {
		t.Fatalf("exact id status: %+v updated=%v err=%v", wf, updated, err)
	}
	stored, found = s.IncidentStatus("canonical")
	if !found || stored.Status != "resolved" || stored.ResolutionNote != "rotated" {
		t.Fatalf("exact id status wrote the alias incident: %+v found=%v", stored, found)
	}
	exact, found := s.IncidentStatus("listed")
	if !found || exact.Status != "acknowledged" {
		t.Fatalf("exact row status: %+v found=%v", exact, found)
	}

	if _, updated, err := s.SetIncidentStatusResult("absent", "acknowledged", ""); err != nil || updated {
		t.Fatalf("missing status: updated=%v err=%v", updated, err)
	}
	if _, _, err := s.SetIncidentStatusResult("listed", "nope", ""); !errors.Is(err, ErrInvalidIncidentStatus) {
		t.Fatalf("invalid status: %v", err)
	}
}
