package store

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateSchemaGolden = flag.Bool("update-schema-golden", false, "rewrite testdata/schema.golden")

// schemaShape lists every table's columns (name, type, not null, default)
// and every named index's definition, sorted, so two databases compare by
// value.
func schemaShape(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out []string
	rows, err := db.Query(`SELECT type, name, COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index') ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	type object struct{ kind, name, sql string }
	var objects []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.sql); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, o)
	}
	rows.Close()
	for _, o := range objects {
		if o.kind == "index" {
			out = append(out, "index "+o.name+": "+strings.Join(strings.Fields(o.sql), " "))
			continue
		}
		cols, err := db.Query(`SELECT name, type, "notnull", COALESCE(dflt_value,'') FROM pragma_table_info(?)`, o.name)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for cols.Next() {
			var name, typ, def string
			var notNull int
			if err := cols.Scan(&name, &typ, &notNull, &def); err != nil {
				t.Fatal(err)
			}
			names = append(names, fmt.Sprintf("%s %s notnull=%d default=%s", name, strings.ToUpper(typ), notNull, def))
		}
		cols.Close()
		sort.Strings(names)
		out = append(out, "table "+o.name+": "+strings.Join(names, "; "))
	}
	return strings.Join(out, "\n") + "\n"
}

// The schema a fresh database gets is pinned, so restructuring the schema
// code is checked against it.
func TestFreshSchemaMatchesGolden(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := schemaShape(t, s.db)
	golden := filepath.Join("testdata", "schema.golden")
	if *updateSchemaGolden {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("fresh schema differs from %s (rerun with -update-schema-golden only for an intended change)", golden)
	}
}

// A database from before every additive column and index upgrades to the
// same columns and indexes as a fresh one.
func TestLegacyDatabaseUpgradesToTheFreshColumns(t *testing.T) {
	path := migrationFixture(t, `CREATE TABLE flags (id TEXT PRIMARY KEY, rule TEXT, severity INT, ts TEXT, pid INT, agent TEXT, evidence TEXT);
	CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind INT, ts TEXT, pid INT, exe_path TEXT, path TEXT, remote_host TEXT, remote_port INT, detail TEXT);
	CREATE TABLE incidents (id TEXT PRIMARY KEY, flag_id TEXT, pid INT, risk TEXT, report_json TEXT, created_at TEXT);
	CREATE TABLE resource_episodes (id INTEGER PRIMARY KEY AUTOINCREMENT, captured_at TEXT NOT NULL, severity TEXT NOT NULL, session_key TEXT NOT NULL, episode_json TEXT NOT NULL);`)
	legacy, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	fresh, err := Open(filepath.Join(t.TempDir(), "fresh.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	columns := func(db *sql.DB, table string) string {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			names = append(names, n)
		}
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	for _, table := range []string{"flags", "events", "incidents", "resource_episodes"} {
		if got, want := columns(legacy.db, table), columns(fresh.db, table); got != want {
			t.Errorf("%s columns after upgrade:\n got %s\nwant %s", table, got, want)
		}
	}
	indexes := func(db *sql.DB) string {
		var names []string
		rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			names = append(names, n)
		}
		return strings.Join(names, ",")
	}
	if got, want := indexes(legacy.db), indexes(fresh.db); got != want {
		t.Errorf("indexes after upgrade:\n got %s\nwant %s", got, want)
	}
}
