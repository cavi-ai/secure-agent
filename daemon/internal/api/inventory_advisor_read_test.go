package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/clutter"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

func TestInventoryAdvisorReadBatchFailureAndRecovery(t *testing.T) {
	for _, kind := range []string{"worktree", "project"} {
		for _, damage := range []string{"corrupt", "unavailable"} {
			t.Run(kind+"/"+damage, func(t *testing.T) {
				root := t.TempDir()
				dbPath := filepath.Join(root, "advice.db")
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
				// Match the store's lock wait while inventory sizing writes its cache.
				db.SetMaxOpenConns(1)
				if _, err := db.Exec(`PRAGMA busy_timeout=3000`); err != nil {
					t.Fatal(err)
				}
				at := time.Now().UTC()
				keys := []string{filepath.Join(root, "first"), filepath.Join(root, "second"), filepath.Join(root, "third")}
				subjectIDs := make([]string, len(keys))
				a := newTestAPI("", st, nil, nil)
				var read func() map[string]model.AdvisorVerdict
				if kind == "worktree" {
					rep := worktreehunter.ScanReport{Repos: []worktreehunter.RepoReport{{Path: root}}}
					for i, key := range keys {
						rep.Repos[0].Worktrees = append(rep.Repos[0].Worktrees, worktreehunter.Worktree{Path: key, Head: "current", Branch: "feat/test", State: worktreehunter.StateKeep})
						subjectIDs[i] = advisor.WorktreeSubjectID(key, "current")
					}
					// Main and HEAD-less rows never receive worktree advice.
					rep.Repos[0].Worktrees = append(rep.Repos[0].Worktrees,
						worktreehunter.Worktree{Path: root, Head: "current", State: worktreehunter.StateMain},
						worktreehunter.Worktree{Path: filepath.Join(root, "headless"), State: worktreehunter.StateKeep})
					before, err := json.Marshal(rep)
					if err != nil {
						t.Fatal(err)
					}
					read = func() map[string]model.AdvisorVerdict {
						t.Helper()
						notes := a.worktreeNotes(rep)
						after, err := json.Marshal(rep)
						if err != nil || !bytes.Equal(before, after) {
							t.Fatal("advice mutated the source worktree report")
						}
						return notes
					}
				} else {
					places := make([]clutter.Place, len(keys))
					for i, key := range keys {
						if err := os.MkdirAll(filepath.Join(key, ".tmp"), 0o700); err != nil {
							t.Fatal(err)
						}
						places[i] = clutter.Place{Path: key, Project: key}
						subjectIDs[i] = advisor.ProjectSubjectID(key)
					}
					a.clutter = clutter.New(st, filepath.Join(root, "home"), func(context.Context) []clutter.Place { return places })
					mux := a.buildMux()
					type coreItem struct{ Project, Kind, Action string }
					var baseline map[string]coreItem
					read = func() map[string]model.AdvisorVerdict {
						t.Helper()
						w := httptest.NewRecorder()
						mux.ServeHTTP(w, httptest.NewRequest("GET", "/cleanup", nil))
						if w.Code != 200 {
							t.Fatalf("read: %d %s", w.Code, w.Body.String())
						}
						var rep clutter.ClutterReport
						if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
							t.Fatal(err)
						}
						if len(rep.Items) != 3 || len(rep.Projects) != 3 || rep.Reclaimed == nil || *rep.Reclaimed != (model.CleanupTotals{}) {
							t.Fatalf("core inventory or totals lost: %+v", rep)
						}
						core := make(map[string]coreItem, len(rep.Items))
						for _, item := range rep.Items {
							core[item.Path] = coreItem{item.Project, item.Kind, item.Action}
						}
						if baseline == nil {
							baseline = core
						} else if !reflect.DeepEqual(core, baseline) {
							t.Errorf("advice changed inventory identities or actions: got %+v, want %+v", core, baseline)
						}
						return rep.Advice
					}
				}
				if read() != nil {
					t.Fatal("missing advice did not retain the nil envelope")
				}
				for _, subject := range subjectIDs {
					if err := st.PutAdvisorVerdict(subject, kind, model.AdvisorVerdict{Assessment: "keep", Rationale: "stored", Confidence: .7, CreatedAt: at}); err != nil {
						t.Fatal(err)
					}
				}
				if damage == "corrupt" {
					_, err = db.Exec(`UPDATE advisor_verdicts SET created_at='invalid' WHERE kind=? AND subject_id IN (?,?)`, kind, subjectIDs[0], subjectIDs[1])
				} else {
					_, err = db.Exec(`ALTER TABLE advisor_verdicts RENAME TO unavailable_advice`)
				}
				if err != nil {
					t.Fatal(err)
				}
				notes := read()
				if damage == "corrupt" {
					v, ok := notes[keys[2]]
					if len(notes) != 1 || !ok || v.Rationale != "stored" || v.Confidence != .7 || !v.CreatedAt.Equal(at) {
						t.Errorf("invalid advice returned or healthy sibling lost: %+v", notes)
					}
				} else if notes != nil {
					t.Errorf("unavailable advice did not retain the nil envelope: %+v", notes)
				}
				h := st.WriteHealth()
				if h.ReadFailures != 1 || !slices.Contains(h.ReadActive, kind+" advisor verdicts") {
					t.Errorf("batch fault lost or counted per row: %+v", h)
				}
				if damage == "corrupt" {
					_, err = db.Exec(`UPDATE advisor_verdicts SET created_at=? WHERE kind=? AND subject_id IN (?,?)`, at.Format(time.RFC3339Nano), kind, subjectIDs[0], subjectIDs[1])
				} else {
					_, err = db.Exec(`ALTER TABLE unavailable_advice RENAME TO advisor_verdicts`)
				}
				if err != nil {
					t.Fatal(err)
				}
				notes = read()
				if len(notes) != 3 {
					t.Errorf("advice did not return after repair: %+v", notes)
				}
				for _, key := range keys {
					if notes[key].Rationale != "stored" {
						t.Errorf("repair lost advice for %s", key)
					}
				}
				if got := st.WriteHealth(); got.ReadFailures != h.ReadFailures || len(got.ReadActive) != 0 {
					t.Errorf("repair lost failure history: %+v", got)
				}
			})
		}
	}
}
