package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Every flag an incident absorbs resolves to it, beyond the flag_ids kept
// in the row; a flag absorbed again does not count twice; deleting the
// incident drops its links.
func TestIncidentLinksOutlastTheFlagIDsCap(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Now().UTC()
	if err := s.PutIncident(model.IncidentReport{ID: "inc-1", FlagID: "f-0", Timestamp: at}); err != nil {
		t.Fatal(err)
	}
	n := maxIncidentFlagIDs + 20
	for i := 1; i <= n; i++ {
		if _, ok := s.AggregateIntoIncident("inc-1", fmt.Sprint("f-", i), at.Add(time.Duration(i)*time.Second)); !ok {
			t.Fatalf("aggregate f-%d failed", i)
		}
	}
	var stored int
	if err := s.db.QueryRow(`SELECT json_array_length(flag_ids) FROM incidents WHERE id='inc-1'`).Scan(&stored); err != nil || stored != maxIncidentFlagIDs {
		t.Fatalf("flag_ids holds %d (%v), want the cap %d", stored, err, maxIncidentFlagIDs)
	}
	for _, f := range []string{"f-0", "f-1", fmt.Sprint("f-", n)} {
		if id, found, err := s.IncidentIDForFlag(f); err != nil || !found || id != "inc-1" {
			t.Fatalf("flag %s resolves to %q %v %v, want inc-1", f, id, found, err)
		}
	}
	rep, ok := s.AggregateIntoIncident("inc-1", "f-1", at.Add(time.Hour))
	if !ok || rep.AggregateCount != n+1 {
		t.Fatalf("replay of an evicted flag: count %d ok %v, want %d", rep.AggregateCount, ok, n+1)
	}
	if _, err := s.db.Exec(`DELETE FROM incidents WHERE id='inc-1'`); err != nil {
		t.Fatal(err)
	}
	var links int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM incident_flags`).Scan(&links); err != nil || links != 0 {
		t.Fatalf("links after delete = %d (%v)", links, err)
	}
}

// A database from before the link table is linked from its incidents when
// it is opened.
func TestIncidentLinksBackfillFromExistingIncidents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutIncident(model.IncidentReport{ID: "inc-1", FlagID: "f-0", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TRIGGER incident_flags_insert`, `DROP TRIGGER incident_flags_update`, `DROP TRIGGER incident_flags_delete`, `DROP TABLE incident_flags`,
		`UPDATE incidents SET flag_ids='["f-0","f-7"]' WHERE id='inc-1'`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if id, found, err := s.IncidentIDForFlag("f-7"); err != nil || !found || id != "inc-1" {
		t.Fatalf("backfilled link: %q %v %v", id, found, err)
	}
}
