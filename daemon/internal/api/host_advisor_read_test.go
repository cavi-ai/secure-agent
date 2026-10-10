package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/agents"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestHostAdvisorReadBatchFailureAndRecovery(t *testing.T) {
	for _, path := range []string{"/allowlist/suggestions", "/egress/uninspected?limit=2", "/snapshot"} {
		for _, damage := range []string{"corrupt", "unavailable"} {
			t.Run(path+"/"+damage, func(t *testing.T) {
				cfg, err := config.Load("/nonexistent")
				if err != nil {
					t.Fatal(err)
				}
				tg := agents.New(cfg, allowlistProcSource{})
				tg.Refresh()
				cr := correlate.New(tg, sensitive.New(cfg), cfg, correlate.Hooks{})
				dbPath := filepath.Join(t.TempDir(), "host-advice.db")
				st, err := store.Open(dbPath, "")
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				at := time.Now().UTC()
				for i, host := range []string{"203.0.113.5", "203.0.113.6"} {
					for n := 0; n < 4-i; n++ {
						cr.Observe(event.Event{Kind: event.KindConnOpen, PID: 42, TS: at, RemoteHost: host, RemotePort: 443})
					}
					if err := st.PutAdvisorVerdict("host:cursor|"+host, "host", model.AdvisorVerdict{Rationale: "stored", CreatedAt: at}); err != nil {
						t.Fatal(err)
					}
				}
				if damage == "corrupt" {
					_, err = db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE subject_id='host:cursor|203.0.113.5'`)
				} else {
					_, err = db.Exec(`ALTER TABLE advisor_verdicts RENAME TO unavailable_advice`)
				}
				if err != nil {
					t.Fatal(err)
				}
				a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
				a.correlator = cr
				request := func(degraded bool) []Suggestion {
					t.Helper()
					w := httptest.NewRecorder()
					a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
					if w.Code != 200 {
						t.Fatalf("read: %d %s", w.Code, w.Body.String())
					}
					var rows []Suggestion
					if path == "/snapshot" {
						var snapshot Snapshot
						if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
							t.Fatal(err)
						}
						rows = snapshot.Suggestions
						if degraded {
							if snapshot.Status.StorageHealth == nil || !slices.Contains(snapshot.Status.StorageHealth.ReadActive, "host advisor verdicts") {
								t.Error("snapshot status omitted current host read failure")
							}
							if snapshot.Posture.CoverageCount != 1 || len(snapshot.Posture.CoverageItems) != 1 || !strings.Contains(snapshot.Posture.CoverageItems[0].Detail, "host advisor verdicts") {
								t.Errorf("first snapshot hid host read failure: %+v", snapshot.Posture)
							}
						} else if snapshot.Posture.CoverageCount != 0 {
							t.Errorf("snapshot did not recover: %+v", snapshot.Posture)
						}
					} else if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
						t.Fatal(err)
					}
					if len(rows) != 2 || rows[0].Host != "203.0.113.5" || rows[0].Count != 4 || rows[1].Host != "203.0.113.6" || rows[1].Count != 3 {
						t.Fatalf("core endpoints or ordering changed: %+v", rows)
					}
					return rows
				}
				rows := request(true)
				if rows[0].Rationale != "" || (damage == "corrupt" && rows[1].Rationale != "stored") || (damage == "unavailable" && rows[1].Rationale != "") {
					t.Errorf("invalid advice or healthy sibling lost: %+v", rows)
				}
				h := st.WriteHealth()
				if h.ReadFailures != 1 || !slices.Contains(h.ReadActive, "host advisor verdicts") {
					t.Errorf("host batch fault lost or counted per row: %+v", h)
				}
				if damage == "corrupt" {
					_, err = db.Exec(`UPDATE advisor_verdicts SET created_at=? WHERE subject_id='host:cursor|203.0.113.5'`, at.Format(time.RFC3339Nano))
				} else {
					_, err = db.Exec(`ALTER TABLE unavailable_advice RENAME TO advisor_verdicts`)
				}
				if err != nil {
					t.Fatal(err)
				}
				rows = request(false)
				if rows[0].Rationale != "stored" || rows[1].Rationale != "stored" {
					t.Error("advice did not return after repair")
				}
				if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
					t.Errorf("repair lost failure history: %+v", got)
				}
			})
		}
	}
}
