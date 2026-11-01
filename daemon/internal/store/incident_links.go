package store

import (
	"database/sql"
	"fmt"
)

// incident_flags links each incident to every flag it holds (its opening
// flag_id and each aggregated one), so a flag's incident is an index seek
// rather than a json_each over every incident's flag_ids. Triggers on
// incidents keep it in step with every write and delete; flag_ids keeps only
// the most recent maxIncidentFlagIDs for older readers, and aggregate_count
// stays the true total.
const maxIncidentFlagIDs = 256

// incidentFlagIDsArray is flag_ids when it is a JSON array, else '[]': a
// damaged column must not fail the write that carries it.
func incidentFlagIDsArray(col string) string {
	return `(CASE WHEN json_valid(` + col + `) AND json_type(` + col + `)='array' THEN ` + col + ` ELSE '[]' END)`
}

var incidentLinkSchema = []string{
	`CREATE TABLE IF NOT EXISTS incident_flags (
		flag_id TEXT NOT NULL,
		incident_id TEXT NOT NULL,
		PRIMARY KEY (flag_id, incident_id)
	) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS idx_incident_flags_incident ON incident_flags(incident_id)`,
	`CREATE TRIGGER IF NOT EXISTS incident_flags_insert AFTER INSERT ON incidents BEGIN
		INSERT OR IGNORE INTO incident_flags(flag_id, incident_id) SELECT NEW.flag_id, NEW.id WHERE COALESCE(NEW.flag_id,'') != '';
		INSERT OR IGNORE INTO incident_flags(flag_id, incident_id)
			SELECT value, NEW.id FROM json_each(` + incidentFlagIDsArray("NEW.flag_ids") + `) WHERE type = 'text';
	END`,
	`CREATE TRIGGER IF NOT EXISTS incident_flags_update AFTER UPDATE OF flag_ids ON incidents BEGIN
		INSERT OR IGNORE INTO incident_flags(flag_id, incident_id)
			SELECT value, NEW.id FROM json_each(` + incidentFlagIDsArray("NEW.flag_ids") + `) WHERE type = 'text';
	END`,
	`CREATE TRIGGER IF NOT EXISTS incident_flags_delete AFTER DELETE ON incidents BEGIN
		DELETE FROM incident_flags WHERE incident_id = OLD.id;
	END`,
}

// createIncidentLinks creates the link table and its triggers and fills it
// from existing incidents when it is empty (a database from before it).
func createIncidentLinks(tx *sql.Tx) error {
	for _, q := range incidentLinkSchema {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("create incident links: %w", err)
		}
	}
	var linked int
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM incident_flags)`).Scan(&linked); err != nil {
		return fmt.Errorf("inspect incident links: %w", err)
	}
	if linked == 1 {
		return nil
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO incident_flags(flag_id, incident_id)
		SELECT flag_id, id FROM incidents WHERE COALESCE(flag_id,'') != ''
		UNION SELECT je.value, i.id FROM incidents i, json_each(` + incidentFlagIDsArray("i.flag_ids") + `) je WHERE je.type = 'text'`); err != nil {
		return fmt.Errorf("backfill incident links: %w", err)
	}
	return nil
}

// incidentsForFlagSQL selects the incidents linked to a flag (bind the flag
// id). Lookups keep flag_id = ? beside it (idx_incidents_flag): a row whose
// identity was damaged still reads as a fault, not as absent.
const incidentsForFlagSQL = `SELECT incident_id FROM incident_flags WHERE flag_id = ?`
