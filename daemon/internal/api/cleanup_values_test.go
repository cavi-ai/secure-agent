package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestCleanupLedgerValuesAreHistoryNotCurrentTrash(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	const gb = int64(1 << 30)
	const trashBytes = 516*gb + 100*(1<<20)
	trashItem := filepath.Join(t.TempDir(), "trashed-item")
	if err := os.WriteFile(trashItem, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []model.CleanupEntry{
		{TS: now.Add(-40 * 24 * time.Hour), Action: "worktree-remove", Bytes: 7 * gb},
		{TS: now.Add(-40 * 24 * time.Hour), Action: "trash:tmp", Bytes: 512 * gb},
		{TS: now, Action: "worktree-remove", Bytes: 2 * gb},
		{TS: now, Action: "clean:go", Bytes: 3 * gb},
		{TS: now, Action: "worktree-prune"},
		{TS: now, Action: "trash:tmp", Bytes: trashBytes - 512*gb, Detail: "moved to " + trashItem},
		{TS: now, Action: "ask:pr", Bytes: 999 * gb},
	} {
		row.Path = "/fixture/source"
		st.PutCleanup(row)
	}
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true} })
	read := func(limit string) (model.CleanupTotals, []model.CleanupDay) {
		t.Helper()
		w := httptest.NewRecorder()
		a.buildMux().ServeHTTP(w, httptest.NewRequest("GET", "/cleanup/ledger?days=2&limit="+limit, nil))
		var response struct {
			Totals  model.CleanupTotals  `json:"totals"`
			Daily   []model.CleanupDay   `json:"daily"`
			Entries []model.CleanupEntry `json:"entries"`
		}
		if w.Code != http.StatusOK {
			t.Fatalf("ledger: %d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if limit == "1" && len(response.Entries) != 1 {
			t.Fatalf("history limit not applied: %+v", response.Entries)
		}
		return response.Totals, response.Daily
	}
	wantTotals := model.CleanupTotals{Bytes: 12 * gb, Count: 4, Bytes30d: 5 * gb, Count30d: 3,
		TrashedBytes: trashBytes, TrashedCount: 2}
	wantDays := []model.CleanupDay{
		{Day: now.AddDate(0, 0, -1).Format(time.DateOnly)},
		{Day: now.Format(time.DateOnly), Bytes: 5 * gb, Count: 3, TrashedBytes: trashBytes - 512*gb, TrashedCount: 1},
	}
	for _, limit := range []string{"1", "100"} {
		totals, daily := read(limit)
		if totals != wantTotals || !reflect.DeepEqual(daily, wantDays) {
			t.Fatalf("limit=%s totals=%+v daily=%+v", limit, totals, daily)
		}
	}
	// Removing a fixture from Trash cannot rewrite recorded moves or claim
	// additional freed bytes. The ledger is not a current Trash inventory.
	if err := os.Remove(trashItem); err != nil {
		t.Fatal(err)
	}
	totals, daily := read("1")
	if totals != wantTotals || !reflect.DeepEqual(daily, wantDays) {
		t.Fatalf("emptying Trash changed history: totals=%+v daily=%+v", totals, daily)
	}
}
