package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
)

// Discovery carries this machine's profile and the ranked recommendations
// next to the servers and the managed catalog ids.
func TestAdvisorDiscoverRecommends(t *testing.T) {
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	w := httptest.NewRecorder()
	a.handleAdvisorDiscover(w, httptest.NewRequest(http.MethodGet, "/advisor/discover", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Servers         []advisor.DiscoveredServer `json:"servers"`
		ManagedModels   []string                   `json:"managed_models"`
		Machine         advisor.Machine            `json:"machine"`
		Recommendations []advisor.Recommendation   `json:"recommendations"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Machine.RAMBytes == 0 || body.Recommendations == nil || !slices.Equal(body.ManagedModels, advisor.DefaultManagedModels) {
		t.Fatalf("machine=%+v recs=%d managed=%v", body.Machine, len(body.Recommendations), body.ManagedModels)
	}
	managed := 0
	for _, r := range body.Recommendations {
		if r.Source == "managed" {
			managed++
		}
	}
	if managed != len(advisor.Catalog) {
		t.Fatalf("%d managed recommendations, want %d", managed, len(advisor.Catalog))
	}
}
