package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
)

// TestMuteListCarriesTitle: GET /mute rows carry the rule's human title so
// clients render it without a private rule table; POST still takes only
// {rule, host}.
func TestMuteListCarriesTitle(t *testing.T) {
	dir := t.TempDir()
	a := newTestAPI(filepath.Join(dir, "d.sock"), testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	a.mutes = correlate.NewMuteStore(filepath.Join(dir, "muted.json"))

	post := httptest.NewRecorder()
	a.handleMute(post, httptest.NewRequest(http.MethodPost, "/mute",
		strings.NewReader(`{"rule":"keychain-access","host":"*"}`)))
	if post.Code != http.StatusOK {
		t.Fatalf("mute post = %d %s", post.Code, post.Body.String())
	}
	unknown := httptest.NewRecorder()
	a.handleMute(unknown, httptest.NewRequest(http.MethodPost, "/mute",
		strings.NewReader(`{"rule":"novel-rule","host":"api.example.com"}`)))
	if unknown.Code != http.StatusOK {
		t.Fatalf("mute post = %d %s", unknown.Code, unknown.Body.String())
	}

	get := httptest.NewRecorder()
	a.handleMute(get, httptest.NewRequest(http.MethodGet, "/mute", nil))
	var rows []map[string]string
	if err := json.Unmarshal(get.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v (%s)", err, get.Body.String())
	}
	want := map[string]string{
		"keychain-access": "Agent touched the keychain",
		"novel-rule":      "novel-rule",
	}
	if len(rows) != len(want) {
		t.Fatalf("rows = %v", rows)
	}
	for _, r := range rows {
		if r["title"] != want[r["rule"]] {
			t.Fatalf("rule %q title = %q, want %q", r["rule"], r["title"], want[r["rule"]])
		}
	}
}
