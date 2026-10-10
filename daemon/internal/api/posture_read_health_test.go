package api

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestPostureReadFailureVisibleOnFirstPassAndRecovery(t *testing.T) {
	for _, damage := range []string{"incident report", "incident workflow", "noncritical flag"} {
		for _, surface := range []string{"http", "fleet", "delta"} {
			t.Run(damage+"/"+surface, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "posture.db")
				st, err := store.Open(path, "")
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				incident := model.IncidentReport{ID: "incident", FlagID: "flag", Risk: model.RiskLow, Timestamp: time.Now()}
				flag := model.Flag{ID: "flag", Rule: "keychain-access", Severity: 1, PID: 1, TS: time.Now()}
				label := "incidents"
				var savedReport string
				switch damage {
				case "noncritical flag":
					label = "flags"
					if _, err := st.PutFlag(flag); err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec("UPDATE flags SET pid='invalid'"); err != nil {
						t.Fatal(err)
					}
				default:
					if err := st.PutIncident(incident); err != nil {
						t.Fatal(err)
					}
					if err := db.QueryRow("SELECT report_json FROM incidents WHERE id='incident'").Scan(&savedReport); err != nil {
						t.Fatal(err)
					}
					q := "UPDATE incidents SET report_json='invalid'"
					if damage == "incident workflow" {
						q, label = "UPDATE incidents SET status=NULL", "incident workflows"
					}
					if _, err := db.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
				a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
				a.deltaHub = NewDeltaHub()
				defer a.deltaHub.Close()
				ch := a.deltaHub.Subscribe()
				read := func() Posture {
					t.Helper()
					switch surface {
					case "http":
						w := httptest.NewRecorder()
						a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/posture", nil))
						if w.Code != 200 {
							t.Fatalf("posture response: %d %s", w.Code, w.Body.String())
						}
						var p Posture
						if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
							t.Fatal(err)
						}
						return p
					case "fleet":
						return a.CurrentPosture()
					default:
						a.PublishPostureIfChanged()
						select {
						case d := <-ch:
							p, ok := d.Data.(Posture)
							if d.Type != "posture" || !ok {
								t.Fatalf("delta: %+v", d)
							}
							return p
						default:
							t.Fatal("failure/recovery did not publish a posture delta")
						}
					}
					return Posture{}
				}
				p := read()
				if p.State != "attention" || p.NeedsYou != 0 || p.CoverageCount != 1 || len(p.CoverageItems) != 1 || p.CoverageItems[0].Kind != "storage_read_failure" || !strings.Contains(p.CoverageItems[0].Detail, label) {
					t.Errorf("first pass hid %s: %+v", damage, p)
				}
				failed := st.WriteHealth().ReadFailures
				if failed == 0 {
					t.Fatal("read failure was not counted")
				}
				if damage == "noncritical flag" && len(st.WriteHealth().ReadActive) != 0 {
					t.Fatal("calculation-local fault mutated runtime read health after a successful narrower read")
				}
				if damage == "noncritical flag" {
					if _, err := st.PutFlag(flag); err != nil {
						t.Fatal(err)
					}
				} else if _, err := db.Exec("UPDATE incidents SET report_json=?, status='open' WHERE id='incident'", savedReport); err != nil {
					t.Fatal(err)
				}
				p = read()
				if p.State != "all-clear" || p.NeedsYou != 0 || p.CoverageCount != 0 {
					t.Errorf("first recovery pass remained stale: %+v", p)
				}
				if h := st.WriteHealth(); h.ReadFailures != failed || len(h.ReadActive) != 0 || h.Failures != 0 {
					t.Fatalf("recovery health: %+v", h)
				}
			})
		}
	}
}

func TestPostureReadFailureRetainsKnownDecisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.PutFlag(model.Flag{ID: "critical", Rule: "transcript-secret-leak", Severity: 3, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutIncident(model.IncidentReport{ID: "bad", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE incidents SET report_json='invalid'"); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	p := a.CurrentPosture()
	if p.State != "critical" || p.NeedsYou != 1 || p.CoverageCount != 1 || len(p.Items) != 1 || p.Items[0].ID != "critical" {
		t.Fatalf("unavailable history hid a known critical decision: %+v", p)
	}
	count := 0
	for _, group := range p.Groups {
		count += len(group.Items)
	}
	if count != p.NeedsYou {
		t.Fatalf("group invariant: %d items, needs_you=%d", count, p.NeedsYou)
	}
}

func TestSnapshotPostureReportsFailureInWiderAttentionRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "posture.db")
	st, err := store.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.PutFlag(model.Flag{ID: "old", Rule: "keychain-access", Severity: 3, PID: 1, TS: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE flags SET pid='invalid'"); err != nil {
		t.Fatal(err)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/snapshot", nil))
	if w.Code != 200 {
		t.Fatalf("primary sections should be readable: %d %s", w.Code, w.Body.String())
	}
	var snapshot Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if p := snapshot.Posture; p.State != "attention" || p.CoverageCount != 1 {
		t.Fatalf("snapshot headline hid failed wider attention query: %+v", p)
	}
}
